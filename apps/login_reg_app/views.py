from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import bcrypt

def index(request):


	return render(request, "login_reg_app/index.html")

def success(request):
	if 'user_id' in request.session:

		user = User.objects.get(id=request.session['user_id'])
		
		context = {
		'user': user
		}

		return render(request, 'login_reg_app/success.html', context)

	return redirect('/')

def register(request):
	if request.method == 'POST':

		errors = User.objects.validateRegistration(request.POST)

		if not errors:
			user = User.objects.createUser(request.POST)

			request.session['user_id'] = user.id

			return redirect('/success')

		for error in errors:
			messages.error(request, error)
		print errors

	return redirect('/')

def login(request):
	if request.method == 'POST':
		errors = User.objects.validateLogin(request.POST)

		if not errors:
			user = User.objects.filter(email = request.POST['email']).first()

			if user:
				password = str(request.POST['password'])
				user_password = str(user.password)

				hashed_pw = bcrypt.hashpw(password, user_password)

				if hashed_pw == user.password:
					request.session['user_id'] = user.id

					print request.session['user_id']
					return redirect('/success')

			errors.append('Invalid account information.')
		
		for error in errors:
			messages.error(request, error)


		print request.session['user_id']
		return redirect('/')

		

		print errors


def logout(request):
	if 'user_id' in request.session:
		request.session.pop('user_id')

	return redirect('/')