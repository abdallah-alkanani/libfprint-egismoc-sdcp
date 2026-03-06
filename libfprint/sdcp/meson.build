sdcp_truststore_gresource_xml = custom_target('sdcp-truststore.gresource',
    input : 'generate-gresource.py',
    output : 'sdcp-truststore.gresource.xml',
    command : [find_program('python3'), '@INPUT@', meson.current_source_dir(), '@OUTPUT@'],
)

sdcp_truststore_resource = gnome.compile_resources(
    'fpi-sdcp-truststore-resource',
    sdcp_truststore_gresource_xml,
    c_name: 'fpi_sdcp_truststore',
)
