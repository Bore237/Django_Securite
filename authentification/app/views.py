from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from .token import generatorToken

from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from authentification.settings import EMAIL_HOST_USER
from django.core.mail import send_mail, EmailMessage
# Create your views here.

nameUser = ''


def home(request):
    return render(request, 'app/index.html', {'firstname': nameUser})


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        lastname = request.POST['lastname']
        firstname = request.POST['firstname']
        email = request.POST['email']
        password = request.POST['password']
        password1 = request.POST['password1']
        # Empécher la rédodance des nom utilisateur
        if User.objects.filter(username=username):
            messages.error(request, "ce nom a deja été pris")
            return redirect('register')
        if User.objects.filter(email=email):
            messages.error(request, "cette email a deja un compte")
            return redirect('register')
        if not username.isalnum():  # verifier que ce n'est pas alpha numérique
            messages.error(request, "Le nom doit etre alpha numerique")
            return redirect('register')

        if password1 != password:
            messages.error(request, "Les deux password ne coinside pas")
            return redirect('register')

        nom_utilisateur = User.objects.create_user(username, email, password)
        nom_utilisateur.first_name = firstname
        nom_utilisateur.last_name = lastname
        nom_utilisateur.is_active = False
        nom_utilisateur.save()
        messages.success(request, 'Votre compte a été créer avec sucess')

        # Envoyer un email a utilisateur
        subject = "Bienvenu sur Borel store login"
        message = "Welcome" + " " + nom_utilisateur.last_name + \
            "\n Nous somme heureux de vous compter parmi nous\n\n\n Merci!" "\n"
        from_email = EMAIL_HOST_USER
        to_list = [nom_utilisateur.email]
        send_mail(subject, message, from_email, to_list, fail_silently=False)

        # mail de confirmation (get curent sign)
        # Le lien du site:
        current_site = get_current_site(request)
        email_subject = "Confirmation  votre inscription"
        # le fichier pour la confirmation, le domaine , id(sera coder avec encode force byte dependant
        # du pk)
        messageConfirm = render_to_string("emailConfir.html", {
            "name": nom_utilisateur.first_name,
            "domain": current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(nom_utilisateur.pk)),
            'token': generatorToken.make_token(nom_utilisateur),
        })

        print(messageConfirm)

        send_mail(email_subject, messageConfirm,
                  from_email, to_list, fail_silently=True)
        email = EmailMessage(email_subject,
                             messageConfirm,
                             from_email,
                             to_list
                             )

        email.send()
        return redirect('login')

    return render(request, 'app/register.html')


def logIn(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        my_user = User.objects.get(username=username)
        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            firstname = user.first_name
            render(request, 'app/login.html', {'firstname': firstname})
            messages.success(request, 'Welcome to you section')
            return redirect('home')
        elif my_user.is_active == False:
            messages.error(
                request, "Il faut confirmer votre adres mail avant de vous connecter")
            return redirect('login')
        else:
            messages.error(request, 'Connection fail with this compte')
            return redirect('login')

    return render(request, 'app/login.html')


def logOut(request):
    logout(request)
    messages.success(request, 'vous avez etez bien deconnecter')
    return redirect('home')


def activate(request, uidb64, token):
    try:
        # decoder id pour voir s'il corepond au user
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and generatorToken.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(
            request, "Felicitation vous venez d'activer votre compte")
        return redirect('login')
    else:
        messages.error(request, '---activation echoue---')
        return redirect('home')
