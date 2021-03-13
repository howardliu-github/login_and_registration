from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
import bcrypt

# Create your views here.
def index(request):
    return render(request, "index.html")

def success(request):
    # if userid exists, page will display info - if not it will redirect to home page
    if "userid" in request.session:
        user = User.objects.filter(id=request.session["userid"])
        if user:
            context = {
                "user": user[0]
            }
            return render(request, "success.html", context)
    return redirect("/")

def login(request):
    # filter off of email to check if the user exists
    user = User.objects.filter(
        email=request.POST["email"]
    )
    if user:
        # logged user should be the only user in the list
        logged_user = user[0]
        # compare the passwords, checking plain text encode and hash encode
        if bcrypt.checkpw(request.POST["password"].encode(), logged_user.password.encode()):
            request.session["userid"] = logged_user.id
            return redirect("/success")
        else:
            messages.error(request, "We don't recognize that email address and/or password.")
    else:
        messages.error(request, "We don't recognize that email address and/or password.")
    return redirect("/")

def logout(request):
    request.session.flush()
    return redirect('/')

def register(request):
    # if request is a POST do all this
    if request.method == "POST":
        # calls basic_validator in models, if there are any errors it will display messages
        errors = User.objects.basic_validator(request.POST)
        
        # if someone is trying to register with an email that already exists
        if User.objects.filter(email = request.POST["email"]):
            messages.error(request, "Email is already registered and can be used to login!")
            return redirect("/")
            
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect("/")
        
        # if no issues, will create new user object
        else:
            # store plain text password in a variable
            password = request.POST["password"]
            # .hashpw is a function of bcrypt that hashes the password
            # .encode encodes the password variable
            # .gensalt creates a salt (can be hashed # of times ex. .gensalt(20), each number is a function to solve for hackers) 
            # .decode gives result in readable format - without it provides string in bit level, need decode to have string format
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            new_user = User.objects.create(
                first_name = request.POST["first_name"],
                last_name = request.POST["last_name"],
                email = request.POST["email"],
                password = password_hash,
            )
            # assigns session userid for user created
            request.session["userid"] = new_user.id

            return redirect("/success")
        
    # if it is NOT a POST, meaning it is a GET - redirect to main page
    return redirect("/")
