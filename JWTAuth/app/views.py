from django.http import HttpResponse
from datetime import datetime
from datetime import timedelta
import jwt
from JWTAuth import settings
from rest_framework.viewsets import generics
from .models import User
import json
from . import serializers
import bcrypt

salt = bcrypt.gensalt()


class LoginAPIView(generics.GenericAPIView):
    def get(self, request, *args, **kwargs):
        user = User.objects.get(id=request.GET['id'])
        access_token, refresh_token = generate_tokens(user)
        hashed = bcrypt.hashpw(refresh_token, salt)
        user.refresh_token = hashed
        user.save()
        return HttpResponse(json.dumps({
            'access token': access_token.decode('utf-8'),
            'refresh token': refresh_token.decode('utf-8')
        }))


class RefreshAPIView(generics.GenericAPIView):
    serializer_class = serializers.RefreshSerializer

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        old_refresh_token = serializer.validated_data['refresh_token'].encode('utf-8')
        hashed = bcrypt.hashpw(old_refresh_token, salt)
        users = User.objects.all()
        for u in users:
            if u.refresh_token == str(hashed):
                access_token, refresh_token = generate_tokens(u)
                new_hash = bcrypt.hashpw(refresh_token, salt)
                u.refresh_token = new_hash
                u.save()
                return HttpResponse(json.dumps({
                    'access token': access_token.decode('utf-8'),
                    'refresh token': refresh_token.decode('utf-8')
                }))
        return HttpResponse(1)


def generate_tokens(user):
    dt = datetime.now() + timedelta(days=1)
    access_token = jwt.encode({
        'email': user.email,
        'username': user.username,
        'exp': int(dt.strftime('%s'))
    }, settings.SECRET_KEY, algorithm='HS512')

    refresh_token = jwt.encode({
        'username': user.username,
        'exp': int(dt.strftime('%s'))
    }, settings.SECRET_KEY, algorithm='HS512')

    return access_token, refresh_token