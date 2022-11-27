# VS_VERSIONINFO Structure Extractor

This package parses a VS_VERSIONINFO structure and returns a JSON string. Certain szKey members in this struct and its children are compared with the expected and the structs are marked non-standard if the strings are not as expected. Data returned from this parser is meant for malware analysis.

If you need to isolate the RT_VERSION resource for input into this extractor, try [this](https://gist.github.com/utkonos/86585b85a313a2e41d33471c22cc26c6) Jupyter Notebook.

## Usage

### Native Python Dictionary Output

```python
versioninfo.parser.get_versioninfo(data)
```

### JSON Output

```python
versioninfo.parser.to_json(data)
```

#### Bugs

If the parsing fails or there are any other problems, please provide the file that caused the problem in addition to opening a Github issue.
