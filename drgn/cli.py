# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for embedding the drgn CLI."""

import argparse
import builtins
import importlib
import logging
import os
import os.path
import pkgutil
import runpy
import shutil
import sys
from typing import Any, Callable, Dict, Optional, Tuple

import drgn
from drgn.internal.repl import interact, readline
from drgn.internal.rlcompleter import Completer
from drgn.internal.sudohelper import open_via_sudo

__all__ = ("run_interactive", "version_header")

logger = logging.getLogger("drgn")


class _LogFormatter(logging.Formatter):
    _LEVELS = (
        (logging.DEBUG, "debug", "36"),
        (logging.INFO, "info", "32"),
        (logging.WARNING, "warning", "33"),
        (logging.ERROR, "error", "31"),
        (logging.CRITICAL, "critical", "31;1"),
    )

    def __init__(self, color: bool) -> None:
        if color:
            level_prefixes = {
                level: f"\033[{level_color}m{level_name}:\033[0m"
                for level, level_name, level_color in self._LEVELS
            }
        else:
            level_prefixes = {
                level: f"{level_name}:" for level, level_name, _ in self._LEVELS
            }
        default_prefix = "%(levelname)s:"

        self._drgn_formatters = {
            level: logging.Formatter(f"{prefix} %(message)s")
            for level, prefix in level_prefixes.items()
        }
        self._default_drgn_formatter = logging.Formatter(
            f"{default_prefix} %(message)s"
        )

        self._other_formatters = {
            level: logging.Formatter(f"{prefix}%(name)s: %(message)s")
            for level, prefix in level_prefixes.items()
        }
        self._default_other_formatter = logging.Formatter(
            f"{default_prefix}%(name)s: %(message)s"
        )

    def format(self, record: logging.LogRecord) -> str:
        if record.name == "drgn":
            formatter = self._drgn_formatters.get(
                record.levelno, self._default_drgn_formatter
            )
        else:
            formatter = self._other_formatters.get(
                record.levelno, self._default_other_formatter
            )
        return formatter.format(record)


def version_header() -> str:
    """
    Return the version header printed at the beginning of a drgn session.

    The :func:`run_interactive()` function does not include this banner at the
    beginning of an interactive session. Use this function to retrieve one line
    of text to add to the beginning of the drgn banner, or print it before
    calling :func:`run_interactive()`.
    """
    python_version = ".".join(str(v) for v in sys.version_info[:3])
    libkdumpfile = f'with{"" if drgn._with_libkdumpfile else "out"} libkdumpfile'
    return f"drgn {drgn.__version__} (using Python {python_version}, elfutils {drgn._elfutils_version}, {libkdumpfile})"


def _identify_script(path: str) -> str:
    EI_NIDENT = 16
    SIZEOF_E_TYPE = 2

    with open(path, "rb") as f:
        header = f.read(EI_NIDENT + SIZEOF_E_TYPE)

    ELFMAG = b"\177ELF"
    EI_DATA = 5
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2
    ET_CORE = 4

    if len(header) < EI_NIDENT + SIZEOF_E_TYPE or header[:4] != ELFMAG:
        return "other"

    if header[EI_DATA] == ELFDATA2LSB:
        byteorder = "little"
    elif header[EI_DATA] == ELFDATA2MSB:
        byteorder = "big"
    else:
        return "elf"

    e_type = int.from_bytes(
        header[EI_NIDENT : EI_NIDENT + SIZEOF_E_TYPE],
        byteorder,  # type: ignore[arg-type]  # python/mypy#9057
    )
    return "core" if e_type == ET_CORE else "elf"


def _displayhook(value: Any) -> None:
    if value is None:
        return
    setattr(builtins, "_", None)
    if isinstance(value, drgn.Object):
        try:
            text = value.format_(columns=shutil.get_terminal_size((0, 0)).columns)
        except drgn.FaultError as e:
            logger.warning("can't print value: %s", e)
            text = repr(value)
    elif isinstance(value, (drgn.StackFrame, drgn.StackTrace, drgn.Type)):
        text = str(value)
    else:
        text = repr(value)
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        encoded = text.encode(sys.stdout.encoding, "backslashreplace")
        if hasattr(sys.stdout, "buffer"):
            sys.stdout.buffer.write(encoded)
        else:
            text = encoded.decode(sys.stdout.encoding, "strict")
            sys.stdout.write(text)
    sys.stdout.write("\n")
    setattr(builtins, "_", value)


class _DebugInfoOptionAction(argparse.Action):
    _choices: Dict[str, Tuple[str, Any]]

    @staticmethod
    def _bool_options(value: bool) -> Dict[str, Tuple[str, bool]]:
        return {
            option: ("try_" + option.replace("-", "_"), value)
            for option in (
                "module-name",
                "build-id",
                "debug-link",
                "procfs",
                "embedded-vdso",
                "reuse",
                "supplementary",
            )
        }

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        dest = getattr(namespace, self.dest, None)
        if dest is None:
            dest = {}
            setattr(namespace, self.dest, dest)

        for option in values.split(","):
            try:
                name, value = self._choices[option]
            except KeyError:
                raise argparse.ArgumentError(
                    self,
                    f"invalid option: {option!r} (choose from {', '.join(self._choices)})",
                )
            dest[name] = value


class _TryDebugInfoOptionAction(_DebugInfoOptionAction):
    _choices = {
        **_DebugInfoOptionAction._bool_options(True),
        "kmod=depmod": ("try_kmod", drgn.KmodSearchMethod.DEPMOD),
        "kmod=walk": ("try_kmod", drgn.KmodSearchMethod.WALK),
        "kmod=depmod-or-walk": ("try_kmod", drgn.KmodSearchMethod.DEPMOD_OR_WALK),
        "kmod=depmod-and-walk": ("try_kmod", drgn.KmodSearchMethod.DEPMOD_AND_WALK),
    }


class _NoDebugInfoOptionAction(_DebugInfoOptionAction):
    _choices = {
        **_DebugInfoOptionAction._bool_options(False),
        "kmod": ("try_kmod", drgn.KmodSearchMethod.NONE),
    }


def _main() -> None:
    handler = logging.StreamHandler()
    color = hasattr(sys.stderr, "fileno") and os.isatty(sys.stderr.fileno())
    handler.setFormatter(_LogFormatter(color))
    logging.getLogger().addHandler(handler)

    version = version_header()
    parser = argparse.ArgumentParser(prog="drgn", description="Programmable debugger")

    program_group = parser.add_argument_group(
        title="program selection",
    ).add_mutually_exclusive_group()
    program_group.add_argument(
        "-k", "--kernel", action="store_true", help="debug the running kernel (default)"
    )
    program_group.add_argument(
        "-c", "--core", metavar="PATH", type=str, help="debug the given core dump"
    )
    program_group.add_argument(
        "-p",
        "--pid",
        metavar="PID",
        type=int,
        help="debug the running process with the given PID",
    )

    symbol_group = parser.add_argument_group("debugging symbols")
    symbol_group.add_argument(
        "-s",
        "--symbols",
        metavar="PATH",
        type=str,
        action="append",
        help="load debugging symbols from the given file. "
        "If the file does not correspond to a loaded executable, library, or module, "
        "then it is ignored. This option may be given more than once",
    )
    default_symbols_group = symbol_group.add_mutually_exclusive_group()
    default_symbols_group.add_argument(
        "--main-symbols",
        dest="default_symbols",
        action="store_const",
        const={"main": True},
        help="only load debugging symbols for the main executable "
        "and those added with -s or --extra-symbols",
    )
    default_symbols_group.add_argument(
        "--no-default-symbols",
        dest="default_symbols",
        action="store_const",
        const={},
        help="don't load any debugging symbols that were not explicitly added "
        "with -s or --extra-symbols",
    )
    symbol_group.add_argument(
        "--extra-symbols",
        metavar="PATH",
        type=str,
        action="append",
        help="load additional debugging symbols from the given file, "
        "which is assumed not to correspond to a loaded executable, library, or module. "
        "This option may be given more than once",
    )
    symbol_group.add_argument(
        "--try-symbols-by",
        dest="symbols_by",
        metavar="METHOD[,METHOD...]",
        action=_TryDebugInfoOptionAction,
        help="enable loading debugging symbols using the given methods. "
        "Choices are " + ", ".join(_TryDebugInfoOptionAction._choices) + ". "
        "This option may be given more than once",
    )
    symbol_group.add_argument(
        "--no-symbols-by",
        dest="symbols_by",
        metavar="METHOD[,METHOD...]",
        action=_NoDebugInfoOptionAction,
        help="disable loading debugging symbols using the given methods. "
        "Choices are " + ", ".join(_NoDebugInfoOptionAction._choices) + ". "
        "This option may be given more than once",
    )
    symbol_group.add_argument(
        "--debug-directory",
        dest="debug_directories",
        metavar="PATH",
        type=str,
        action="append",
        help="search for debugging symbols by build ID and debug link in the given directory. "
        "This option may be given more than once",
    )
    symbol_group.add_argument(
        "--no-default-debug-directories",
        action="store_true",
        help="don't search for debugging symbols by build ID and debug link in the standard locations",
    )
    symbol_group.add_argument(
        "--kernel-directory",
        dest="kernel_directories",
        metavar="PATH",
        type=str,
        action="append",
        help="search for the kernel image and loadable kernel modules in the given directory. "
        "This option may be given more than once",
    )
    symbol_group.add_argument(
        "--no-default-kernel-directories",
        action="store_true",
        help="don't search for the kernel image and loadable kernel modules in the standard locations",
    )

    advanced_group = parser.add_argument_group("advanced")
    advanced_group.add_argument(
        "--architecture",
        metavar="ARCH",
        choices=[a.name for a in drgn.Architecture]
        + [a.name.lower() for a in drgn.Architecture],
        help="set the program architecture, in case it can't be auto-detected",
    )
    advanced_group.add_argument(
        "--vmcoreinfo",
        type=str,
        metavar="PATH",
        help="path to vmcoreinfo file (overrides any already present in the file)",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical", "none"],
        default="warning",
        help="log messages of at least the given level to standard error (default: warning)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="log_level",
        action="store_const",
        const="none",
        help="don't print any logs or download progress",
    )
    parser.add_argument(
        "script",
        metavar="ARG",
        type=str,
        nargs=argparse.REMAINDER,
        help="script to execute instead of running in interactive mode",
    )
    parser.add_argument("--version", action="version", version=version)

    args = parser.parse_args()

    if args.script:
        # A common mistake users make is running drgn $core_dump, which tries
        # to run $core_dump as a Python script. Rather than failing later with
        # some inscrutable syntax or encoding error, try to catch this early
        # and provide a helpful message.
        try:
            script_type = _identify_script(args.script[0])
        except OSError as e:
            sys.exit(str(e))
        if script_type == "core":
            sys.exit(
                f"error: {args.script[0]} is a core dump\n"
                f'Did you mean "-c {args.script[0]}"?'
            )
        elif script_type == "elf":
            sys.exit(f"error: {args.script[0]} is a binary, not a drgn script")
    else:
        print(version, file=sys.stderr, flush=True)

    if args.log_level == "none":
        logger.setLevel(logging.CRITICAL + 1)
    else:
        logger.setLevel(args.log_level.upper())

    platform = None
    if args.architecture:
        platform = drgn.Platform(drgn.Architecture[args.architecture.upper()])

    vmcoreinfo = None
    if args.vmcoreinfo is not None:
        with open(args.vmcoreinfo, "rb") as f:
            vmcoreinfo = f.read()

    prog = drgn.Program(platform=platform, vmcoreinfo=vmcoreinfo)
    try:
        if args.core is not None:
            prog.set_core_dump(args.core)
        elif args.pid is not None:
            try:
                prog.set_pid(args.pid or os.getpid())
            except PermissionError as e:
                sys.exit(
                    f"{e}\nerror: attaching to live process requires ptrace attach permissions"
                )
        else:
            try:
                prog.set_kernel()
            except PermissionError as e:
                if shutil.which("sudo") is None:
                    sys.exit(
                        f"{e}\ndrgn debugs the live kernel by default, which requires root"
                    )
                else:
                    prog.set_core_dump(open_via_sudo("/proc/kcore", os.O_RDONLY))
    except OSError as e:
        sys.exit(str(e))
    except ValueError as e:
        # E.g., "not an ELF core file"
        sys.exit(f"error: {e}")

    if args.symbols_by:
        for option, value in args.symbols_by.items():
            setattr(prog.debug_info_options, option, value)

    if args.debug_directories is not None:
        if args.no_default_debug_directories:
            prog.debug_info_options.directories = args.debug_directories
        else:
            prog.debug_info_options.directories = (
                tuple(args.debug_directories) + prog.debug_info_options.directories
            )
    elif args.no_default_debug_directories:
        prog.debug_info_options.directories = ()

    if args.kernel_directories is not None:
        if args.no_default_kernel_directories:
            prog.debug_info_options.kernel_directories = args.kernel_directories
        else:
            prog.debug_info_options.kernel_directories = (
                tuple(args.kernel_directories)
                + prog.debug_info_options.kernel_directories
            )
    elif args.no_default_kernel_directories:
        prog.debug_info_options.kernel_directories = ()

    if args.default_symbols is None:
        args.default_symbols = {"default": True, "main": True}
    try:
        prog.load_debug_info(args.symbols, **args.default_symbols)
    except drgn.MissingDebugInfoError as e:
        logger.warning("\033[1m%s\033[m" if color else "%s", e)

    if args.extra_symbols:
        for extra_symbol_path in args.extra_symbols:
            extra_symbol_path = os.path.abspath(extra_symbol_path)
            module, new = prog.extra_module(extra_symbol_path, create=True)
            if new:
                module.try_file(extra_symbol_path)

    if args.script:
        sys.argv = args.script
        script = args.script[0]
        if pkgutil.get_importer(script) is None:
            sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
        drgn.set_default_prog(prog)
        runpy.run_path(script, init_globals={"prog": prog}, run_name="__main__")
    else:
        run_interactive(prog)


def run_interactive(
    prog: drgn.Program,
    banner_func: Optional[Callable[[str], str]] = None,
    globals_func: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    quiet: bool = False,
) -> None:
    """
    Run drgn's :ref:`interactive-mode` until the user exits.

    This function allows your application to embed the same REPL that drgn
    provides when it is run on the command line in interactive mode.

    :param prog: Pre-configured program to run against. Available as a global
        named ``prog`` in the CLI.
    :param banner_func: Optional function to modify the printed banner. Called
        with the default banner, and must return a string to use as the new
        banner. The default banner does not include the drgn version, which can
        be retrieved via :func:`version_header()`.
    :param globals_func: Optional function to modify globals provided to the
        session. Called with a dictionary of default globals, and must return a
        dictionary to use instead.
    :param quiet: Ignored. Will be removed in the future.

    .. note::

        This function uses :mod:`readline` and modifies some settings.
        Unfortunately, it is not possible for it to restore all settings. In
        particular, it clears the ``readline`` history and resets the TAB
        keybinding to the default.

        Applications using ``readline`` should save their history and clear any
        custom settings before calling this function. After calling this
        function, applications should restore their history and settings before
        using ``readline``.
    """
    init_globals: Dict[str, Any] = {
        "prog": prog,
        "drgn": drgn,
        "__name__": "__main__",
        "__doc__": None,
    }
    drgn_globals = [
        "FaultError",
        "NULL",
        "Object",
        "alignof",
        "cast",
        "container_of",
        "execscript",
        "implicit_convert",
        "offsetof",
        "reinterpret",
        "sizeof",
        "stack_trace",
    ]
    for attr in drgn_globals:
        init_globals[attr] = getattr(drgn, attr)

    banner = f"""\
For help, type help(drgn).
>>> import drgn
>>> from drgn import {", ".join(drgn_globals)}
>>> from drgn.helpers.common import *"""

    module = importlib.import_module("drgn.helpers.common")
    for name in module.__dict__["__all__"]:
        init_globals[name] = getattr(module, name)
    if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
        banner += "\n>>> from drgn.helpers.linux import *"
        module = importlib.import_module("drgn.helpers.linux")
        for name in module.__dict__["__all__"]:
            init_globals[name] = getattr(module, name)

    if banner_func:
        banner = banner_func(banner)
    if globals_func:
        init_globals = globals_func(init_globals)

    old_path = list(sys.path)
    old_displayhook = sys.displayhook
    old_history_length = readline.get_history_length()
    old_completer = readline.get_completer()
    try:
        old_default_prog = drgn.get_default_prog()
    except drgn.NoDefaultProgramError:
        old_default_prog = None
    histfile = os.path.expanduser("~/.drgn_history")
    try:
        readline.clear_history()
        try:
            readline.read_history_file(histfile)
        except OSError as e:
            if not isinstance(e, FileNotFoundError):
                logger.warning("could not read history: %s", e)

        readline.set_history_length(1000)
        readline.parse_and_bind("tab: complete")
        readline.set_completer(Completer(init_globals).complete)

        sys.path.insert(0, "")
        sys.displayhook = _displayhook

        drgn.set_default_prog(prog)

        try:
            interact(init_globals, banner)
        finally:
            try:
                readline.write_history_file(histfile)
            except OSError as e:
                logger.warning("could not write history: %s", e)
    finally:
        drgn.set_default_prog(old_default_prog)
        sys.displayhook = old_displayhook
        sys.path[:] = old_path
        readline.set_history_length(old_history_length)
        readline.parse_and_bind("tab: self-insert")
        readline.set_completer(old_completer)
        readline.clear_history()
