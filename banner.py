# banner.py
VERSION = "v0.0.2"

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
    version_text = "Current subshark version " + VERSION
    # {:>60} right-aligns the text in a 60-character wide space
    print(f"{banner_text}\n{version_text:>60}\n")