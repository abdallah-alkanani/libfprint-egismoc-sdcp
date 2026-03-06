#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET

gresource_prefix = "/org/freedesktop/fprint/SDCP/truststore"
[_, pem_files_list, output] = sys.argv

with open(pem_files_list, 'rt', encoding='utf-8') as f:
    pem_files_list = f.readlines()

gresources = ET.Element('gresources')
gresource = ET.SubElement(gresources, 'gresource', prefix=gresource_prefix)
for file in pem_files_list:
    file = file.strip()
    node = ET.SubElement(gresource, 'file',
                         alias=os.path.basename(file),
                         compressed='true')
    node.text = file

tree = ET.ElementTree(gresources)
ET.indent(tree, space='  ')
with open(output, 'wb') as f:
    tree.write(f, encoding='UTF-8', xml_declaration=True)
