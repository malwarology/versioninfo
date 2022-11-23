# VS_VERSIONINFO Structure Extractor

This package parses a VS_VERSIONINFO structure and returns a JSON string. Certain szKey members in this struct and its children are compared with the expected and the structs are marked non-standard if the strings are not as expected. Data returned from this parser is meant for malware analysis.

# WARNING: THIS LIBRARY IS ALPHA SOFTWARE: ANYTHING CAN CHANGE WITHOUT NOTICE
