import os
import sys
import xml.etree.ElementTree as ET

def check_common(foldername, filename):
    tree = ET.parse(os.path.join(foldername, filename))
    root = tree.getroot()
    namespaces = {'ns': root.tag.split('}')[0].strip('{')}

    # Check <Target Name="GetFrameworkPaths">
    for target in root.findall(".//ns:Target[@Name='GetFrameworkPaths']", namespaces):
        print(f'Found({filename}) <Target Name="GetFrameworkPaths">')

    # Check <COMFileReference Include="...">
    for com_file_ref in root.findall(".//ns:COMFileReference", namespaces):
        include_attr = com_file_ref.get('Include')
        if include_attr:
            print(f'Found({filename}) <COMFileReference Include={include_attr}>')
    
    # Check <PreBuildEvent>
    for pre_build_event in root.findall(".//ns:PreBuildEvent", namespaces):
        for command in pre_build_event.findall(".//ns:Command", namespaces):
            print(f'Found({filename}) PreBuildEvent command: {command.text}')

    # Check <PreLinkEvent>
    for pre_build_event in root.findall(".//ns:PreLinkEvent", namespaces):
        for command in pre_build_event.findall(".//ns:Command", namespaces):
            print(f'Found({filename}) PreLinkEvent command: {command.text}')

    # Check <PostBuildEvent>
    for pre_build_event in root.findall(".//ns:PostBuildEvent", namespaces):
        for command in pre_build_event.findall(".//ns:Command", namespaces):
            print(f'Found({filename}) PostBuildEvent command: {command.text}')

# Check m_serializedClaims
def check_serialized_claims(foldername, filename):
    with open(foldername + "\\" + filename, 'rb') as file:
        content = file.read()
        if b'm_serializedClaims' in content:
            print(f'Found({filename}) m_serializedClaims')

def scan_folder(path):
    for foldername, subfolders, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith('.vcxproj'):
                check_common(foldername, filename)
            elif filename.endswith('.suo'):
                check_serialized_claims(foldername, filename)

def main():
    if len(sys.argv) < 2:
        print('Please input the directory you want to check.')
        return   
    
    path = sys.argv[1]
    scan_folder(path)

if __name__ == '__main__':
    main()
