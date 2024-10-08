project('drgn', 'c', version : '0.0.29')

cc = meson.get_compiler('c')
# TODO: I don't understand what pure means
py = import('python').find_installation(pure : false)

# TODO: figure out drgn/internal/version.py. meson might be able to generate it
# in libdrgn with custom_target(build_always_stale : true) instead.
# TODO: include generated files, build scripts in sdist:
# https://github.com/mesonbuild/meson/issues/2166
# https://github.com/mesonbuild/meson/issues/10118
# TODO: Python unittests
# TODO: vmtest
# TODO: scripts/build_dists.sh. Seems to work except that Python 3.6 fails with
# "ERROR: Could not find a version that satisfies the requirement
# meson-python".
# TODO: test cross-compiling

if get_option('warning_level').to_int() > 0
  add_project_arguments(
    cc.get_supported_arguments(
      '-Wformat-overflow=2',
      '-Wformat-truncation=2',
      '-Wimplicit-fallthrough',
      '-Wmissing-prototypes',
      '-Wpointer-arith',
      '-Wshadow',
      '-Wvla',
      '-Wno-format-zero-length',
    ),
    language : 'c'
  )
endif

add_project_arguments(
  '-D_GNU_SOURCE',
  # TODO: can we get this one from the pyproject.toml or something?
  '-DPACKAGE_BUGREPORT="https://github.com/osandov/drgn/issues"',
  language : 'c'
)

if not cc.compiles('auto x = 1;', name : 'auto')
  if cc.compiles('__auto_type x = 1;', name : '__auto_type')
    add_project_arguments(
      '-Dauto=__auto_type',
      language : 'c'
    )
  else
    error('no auto or __auto_type')
  endif
endif

# Check whether our SWITCH_ENUM() macro works.
if not cc.compiles('''
#include "switch_enum.h"

int main(void)
{
	enum { FOO, BAR } x;
	SWITCH_ENUM(x) {
	case FOO:
	case BAR:
	default:
		break;
	}
	return 0;
}
''',
  name : 'SWITCH_ENUM',
  include_directories : include_directories('libdrgn'),
)
    add_project_arguments(
      '-DSWITCH_ENUM(expr)=switch (expr)',
      language : 'c'
    )
endif

openmp_dep = dependency('openmp', required : get_option('openmp'))

libelf_dep = dependency('libelf', version : '>=0.165')
libdw_dep = dependency('libdw', version : '>=0.165')

libkdumpfile_dep = dependency('libkdumpfile',
                              required : get_option('libkdumpfile'))
if libkdumpfile_dep.found()
  add_project_arguments('-DWITH_LIBKDUMPFILE', language : 'c')
endif

subdir('_drgn_util')
subdir('drgn')
subdir('libdrgn')
