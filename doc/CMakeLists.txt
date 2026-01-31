cmake_minimum_required (VERSION 3.11)

include(GNUInstallDirs)

find_program(ASCIIDOC asciidoc)
if (NOT ASCIIDOC)
  message(FATAL_ERROR "asciidoc required for manpages")
endif(NOT ASCIIDOC)

find_program(A2X a2x)
if (NOT A2X)
  message(FATAL_ERROR "a2x required for manpages")
endif(NOT A2X)

add_custom_target(doc ALL
  COMMAND asciidoc --backend docbook -a "a2x-format=manpage"  --doctype manpage  --out-file  ${PROJECT_BINARY_DIR}/kcron.xml ${PROJECT_SOURCE_DIR}/doc/kcron.doc
  COMMAND a2x --doctype manpage --format manpage  ${PROJECT_BINARY_DIR}/kcron.xml
  COMMENT "Building manpages"
  VERBATIM)

install(FILES ${PROJECT_BINARY_DIR}/kcrondestroy.1 ${PROJECT_BINARY_DIR}/kcroninit.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
