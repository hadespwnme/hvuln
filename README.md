# HVULN

HVuln is a tools for scanning SQLi and XSS, just input URL and this tools will crawl and search SQL or XSS vulnerability on target.

<center>
  <img src="./hvuln.png" style:"width:400px" />
</center>

# Installation

```bash
git clone https://github.com/hadespwnme/hvuln.git
cd hvuln
pip install -r requirements
```


# Usage

```python
python3 hvuln.py <target, ex: http://testphp.vulnweb.com/>
```

You can also use `--verbose` for see each payload being used one by one.