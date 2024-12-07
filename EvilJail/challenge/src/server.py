import subprocess

def pyjail():
    print("-" * 20)
    print("Welcome to Evil Jail! This is a very secure jail.")  
    print("You can go to watch avemujica's PV, if you don't have any idea.")
    print("-" * 20)

    user_input = input("> ") 

    if not all(char in "abcdef" for char in user_input):
        print("Bad Hacker")
        return
    if len(user_input) > 4:
        print("Bad Hacker")
        return

    try:
        result = subprocess.run(
            [user_input],    
            text=True,              
            capture_output=True  
        )
        print("Naup $ ", result.stdout.strip())
    except:
        print("Error!")

if __name__ == "__main__":
    pyjail()
