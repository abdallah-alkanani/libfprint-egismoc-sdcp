#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET

gresource_prefix = "/org/freedesktop/fprint/SDCP/truststore"
[_, file_list, output] = sys.argv

with open(file_list, 'rt', encoding='utf-8') as f:
    # Each line has the format: "<mtime> <path>"
    file_list = [line.strip().split(' ', 1)[1] for line in f if line.strip()]

gresources = ET.Element('gresources')
gresource = ET.SubElement(gresources, 'gresource', prefix=gresource_prefix)
for file in file_list:
    assert os.path.isfile(file), f"The list of files should contain valid file paths: {file}"
    node = ET.SubElement(gresource, 'file',
                         alias=os.path.basename(file),
                         compressed='true')
    node.text = file

tree = ET.ElementTree(gresources)
ET.indent(tree, space='  ')
with open(output, 'wb') as f:
    tree.write(f, encoding='UTF-8', xml_declaration=True)
