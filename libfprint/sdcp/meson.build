# Enumerate all PEM certificate files in the CA store directory,
# including their modification time so downstream targets re-run only
# when a file is actually added, removed, or modified.
sdcp_ca_store_pem_files = custom_target('pem-files',
    command: [
        find_program('find'),
        meson.current_source_dir() / 'ca-store',
        '-type', 'f',
        '-maxdepth', '1',
        '-name', '*.pem',
        '-printf', '%T@ %p\n',
    ],
    output: 'pem-files.list',
    capture: true,
    build_always_stale: true,
)

sdcp_ca_store_gresource_xml = custom_target('ca-store-gresource-xml',
    input : files('generate-gresource.py'),
    output : 'ca-store.gresource.xml',
    command : [
        python3,
        '@INPUT@',
        sdcp_ca_store_pem_files,
        '@OUTPUT@',
    ],
)

sdcp_ca_store_resource = gnome.compile_resources(
    'fpi-sdcp-ca-store-resource',
    sdcp_ca_store_gresource_xml,
    c_name: 'fpi_sdcp_ca_store',
)
