**This project is still under construction**
# Requirements
- Python3 
- Mariadb / MySQL / MongoDB (Optional)

# Install instructions

1. Create a new virtual environment in a folder called 'venv' for this project (This will prevent your binary size and compilation time from being too long).
```bash
python3 -m venv venv
```

2. Activate the virtual environment:
```bash
source venv/bin/activate
```

3. Install the package
```bash
pip install .
```

4. Start LPass
```bash
python3 -m lpass
```
Note: You can also start lpass by executing `lpass` in the terminal directly however this may require modification to the `$PATH` variable


Bonus - If you want to do it all in one step:
```bash
python3 -m venv venv
source venv/bin/activate
pip install .
python3 -m lpass
```
