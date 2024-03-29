find_package(Doxygen REQUIRED)
find_package(Sphinx REQUIRED)


set(DOXYGEN_INPUT_DIR ${CMAKE_SOURCE_DIR}/src)
set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/doxygen)
set(
     DOXYFILE_IN_LIST
     ${CMAKE_CURRENT_SOURCE_DIR}/cfg/cid.cfg
     ${CMAKE_CURRENT_SOURCE_DIR}/cfg/conn.cfg
     ${CMAKE_CURRENT_SOURCE_DIR}/cfg/xquic.cfg
)
# Doxygen won't create this for us
     file(MAKE_DIRECTORY ${DOXYGEN_OUTPUT_DIR})

foreach(DOXYFILE_IN ${DOXYFILE_IN_LIST})
     # rename doxygen output directory
     get_filename_component(DOXYGEN_OUT_FILE ${DOXYFILE_IN} NAME_WE)
     set(
          DOXYFILE_OUT
          ${CMAKE_CURRENT_BINARY_DIR}/cfg/${DOXYGEN_OUT_FILE}
     )

     set(DOXYGEN_INDEX_FILE ${DOXYGEN_OUTPUT_DIR}/${DOXYGEN_OUT_FILE}/index.xml)
     file(MAKE_DIRECTORY ${DOXYGEN_OUTPUT_DIR}/${DOXYGEN_OUT_FILE})

     # Replace variables inside @@ with the current values
     configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT})

     add_custom_command(OUTPUT ${DOXYGEN_INDEX_FILE}
                        DEPENDS ${XQC_SOURCE}
                        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
                        MAIN_DEPENDENCY ${DOXYFILE_OUT} ${DOXYFILE_IN}
                        COMMENT "Generating docs"
                        VERBATIM)
     
     # Nice named target so we can run the job easily
     add_custom_target(Doxygen_${DOXYGEN_OUT_FILE} ALL DEPENDS ${DOXYGEN_INDEX_FILE})
endforeach()


set(SPHINX_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/source)
set(SPHINX_BUILD ${CMAKE_CURRENT_BINARY_DIR}/sphinx)
set(SPHINX_INDEX_FILE ${SPHINX_BUILD}/index.html)


# Only regenerate Sphinx when:
# - Doxygen has rerun
# - Our doc files have been updated
# - The Sphinx config has been updated
add_custom_command(OUTPUT ${SPHINX_INDEX_FILE}
                   COMMAND 
                        ${SPHINX_EXECUTABLE} -b html
                        # Tell Breathe where to find the Doxygen output
                        -Dbreathe_projects.CatCutifier=${DOXYGEN_OUTPUT_DIR}/xml
                   ${SPHINX_SOURCE} ${SPHINX_BUILD}
                   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                   DEPENDS 
                   # Other docs files you want to track should go here (or in some variable)
                   ${SPHINX_SOURCE}/index.rst
                   ${DOXYGEN_INDEX_FILE}
                   MAIN_DEPENDENCY ${SPHINX_SOURCE}/conf.py
                   COMMENT "Generating documentation with Sphinx")

# Nice named target so we can run the job easily
add_custom_target(Sphinx ALL DEPENDS ${SPHINX_INDEX_FILE})

# Add an install target to install the docs
include(GNUInstallDirs)
install(DIRECTORY ${SPHINX_BUILD}
DESTINATION ${CMAKE_INSTALL_DOCDIR})