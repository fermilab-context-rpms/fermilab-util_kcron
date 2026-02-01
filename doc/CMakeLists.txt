cmake_minimum_required (VERSION 3.11)
include(GNUInstallDirs)

find_program(ASCIIDOCTOR asciidoctor)
find_program(ASCIIDOC asciidoc)
find_program(A2X a2x)

if(ASCIIDOCTOR)
  message(STATUS "Using asciidoctor for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/kcroninit.1
    COMMAND ${ASCIIDOCTOR} -b manpage -o ${PROJECT_BINARY_DIR}/kcroninit.1 ${PROJECT_SOURCE_DIR}/doc/kcron.doc
    DEPENDS ${PROJECT_SOURCE_DIR}/doc/kcron.doc
    COMMENT "Building manpage with asciidoctor"
    VERBATIM)
  add_custom_target(doc ALL DEPENDS ${PROJECT_BINARY_DIR}/kcroninit.1)
elseif(ASCIIDOC AND A2X)
  message(STATUS "Using asciidoc/a2x for manpage generation")
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/kcroninit.1
    COMMAND ${ASCIIDOC} --backend docbook -a "a2x-format=manpage" --doctype manpage --out-file ${PROJECT_BINARY_DIR}/kcron.xml ${PROJECT_SOURCE_DIR}/doc/kcron.doc
    COMMAND ${CMAKE_COMMAND} -E env PYTHONWARNINGS=ignore::SyntaxWarning
            ${A2X} --doctype manpage --format manpage ${PROJECT_BINARY_DIR}/kcron.xml
    DEPENDS ${PROJECT_SOURCE_DIR}/doc/kcron.doc
    COMMENT "Building manpage with asciidoc/a2x"
    VERBATIM)
  add_custom_target(doc ALL DEPENDS ${PROJECT_BINARY_DIR}/kcroninit.1)
else()
  message(FATAL_ERROR "Either asciidoctor or both asciidoc and a2x required for manpages")
endif()

# Install the actual manpage
install(FILES ${PROJECT_BINARY_DIR}/kcroninit.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

# Create symlink for kcrondestroy pointing to kcroninit.1
install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink kcroninit.1 \$ENV{DESTDIR}${CMAKE_INSTALL_FULL_MANDIR}/man1/kcrondestroy.1)")
