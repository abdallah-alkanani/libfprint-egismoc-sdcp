sdcp_trust_store_pem_files = custom_target('pem-files',
    command: [
        find_program('find'),
        meson.current_source_dir() / 'truststore',
        '-type', 'f',
        '-maxdepth', '1',
        '-name', '*.pem',
    ],
    output: 'pem-files.list',
    capture: true,
    build_always_stale: true,
)

sdcp_truststore_gresource_xml = custom_target('sdcp-truststore.gresource',
    input : files('generate-gresource.py'),
    output : 'sdcp-truststore.gresource.xml',
    command : [
        python3,
        '@INPUT@',
        sdcp_trust_store_pem_files,
        '@OUTPUT@',
    ],
)

sdcp_truststore_resource = gnome.compile_resources(
    'fpi-sdcp-truststore-resource',
    sdcp_truststore_gresource_xml,
    c_name: 'fpi_sdcp_truststore',
)
