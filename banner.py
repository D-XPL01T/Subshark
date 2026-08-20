# banner.py
VERSION = "v0.0.2"

# ANSI Color codes
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"

def print_version():
    """Prints the version message"""
    print(f"Current subshark version {VERSION}")

def print_banner():
    """Prints the SubShark banner"""
    banner_text = r"""
 $$$$$$\  $$\   $$\ $$$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\  $$$$$$$\  $$\   $$\ 
$$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$ | $$  |
$$ /  \__|$$ |  $$ |$$ |  $$ |$$ /  \__|$$ |  $$ |$$ /  $$ |$$ |  $$ |$$ |$$  / 
\$$$$$$\  $$ |  $$ |$$$$$$$\ |\$$$$$$\  $$$$$$$$ |$$$$$$$$ |$$$$$$$  |$$$$$  /  
 \____$$\ $$ |  $$ |$$  __$$\  \____$$\ $$  __$$ |$$  __$$ |$$  __$$< $$  $$<   
$$\   $$ |$$ |  $$ |$$ |  $$ |$$\   $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |\$$\  
\$$$$$$  |\$$$$$$  |$$$$$$$  |\$$$$$$  |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ | \$$\ 
 \______/  \______/ \_______/  \______/ \__|  \__|\__|  \__|\__|  \__|\__|  \__|
                                                                                
                                                                                """
    version_text = f"Current subshark version {VERSION}"
    dev_text = f"{COLOR_RED}Developed by D - XPL01T{COLOR_RESET}"
    
    # {:>60} right-aligns the text in a 60-character wide space
    print(f"{banner_text}\n{version_text:>60}\n{dev_text:>60}\n")