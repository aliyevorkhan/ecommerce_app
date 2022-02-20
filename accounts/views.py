from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from .models import Account
from .forms import RegistrationForm
from django.http import HttpResponse
# verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

def register(request):
    form = RegistrationForm(request.POST or None)
    if form.is_valid():
        first_name = form.cleaned_data.get('first_name')
        last_name = form.cleaned_data.get('last_name')
        email = form.cleaned_data.get('email')
        phone_number = form.cleaned_data.get('phone_number')
        password = form.cleaned_data.get('password')
        username = email.split('@')[0]
        user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
        user.phone_number = phone_number
        user.save()
        
        # USER ACTIVATION
        current_site = get_current_site(request)
        mail_subject = 'Please activate your account'
        message = render_to_string('accounts/account_verification_email.html', {
            'user': user,
            'domain': current_site,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': default_token_generator.make_token(user),
        })

        to_email = email
        send_email = EmailMessage(mail_subject, message, to=[to_email])
        send_email.send()
        
        # messages.success(request, 'We have sent you a verification email to your email address. Please verify it.')
        return redirect('/accounts/login/?command=verification&email='+email)
    context = {
        'form': form,
    }

    return render(request, "accounts/register.html", context)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            # messages.success(request, 'You are now logged in!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')

    return render(request, "accounts/login.html")

@login_required(login_url = 'login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You successfully logged out!')
    return redirect('login')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email = email).exists():
            user = Account.objects.get(email__exact=email)
            # Reset Password
            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            messages.success(request, 'Password reset email has been sent!')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist!')
            return redirect('forgot_password')
    return render(request, "accounts/forgot_password.html")


@login_required(login_url = 'login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode('utf-8')
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account is activated!')
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link!')
        return redirect('register')

def reset_password_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode('utf-8')
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.info(request, 'Please reset your password')
        return redirect('reset_password')
    else:
        messages.error(request, 'This link has been expired!')
        return redirect('login')

def reset_password(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Passwords do not match')
            return redirect('reset_password')
    else:
        return render(request, 'accounts/reset_password.html')