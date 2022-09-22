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
import base64



class LoginAPIView(generics.GenericAPIView):
    def get(self, request, *args, **kwargs):
        try:
            user = User.objects.get(id=request.GET['id'])
            access_token, refresh_token = generate_tokens(user)
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(refresh_token, salt)
            user.refresh_token = hashed.decode('utf-8')
            user.save()
            return HttpResponse(json.dumps({
                'access token': access_token.decode('utf-8'),
                'refresh token': refresh_token.decode('utf-8')
            }))
        except:
            return HttpResponse('User not found!')


class RefreshAPIView(generics.GenericAPIView):
    serializer_class = serializers.RefreshSerializer

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        old_refresh_token = serializer.validated_data['refresh_token'].encode('utf-8')
        users = User.objects.all()
        try:
            for u in users:
                if bcrypt.checkpw(old_refresh_token, u.refresh_token.encode('utf-8')):
                    access_token, refresh_token = generate_tokens(u)
                    salt = bcrypt.gensalt()
                    new_hash = bcrypt.hashpw(refresh_token, salt)
                    u.refresh_token = new_hash.decode('utf-8')
                    u.save()
                    return HttpResponse(json.dumps({
                        'access token': access_token.decode('utf-8'),
                        'refresh token': refresh_token.decode('utf-8')
                    }))
            return HttpResponse('Token not found!')
        except:
            return HttpResponse('Token not found!')


def generate_tokens(user):
    try:
        dt = datetime.now() + timedelta(days=1)
        dtR = datetime.now() + timedelta(days=1)
        access_token = jwt.encode({
            'email': user.email,
            'username': user.username,
            'exp': int(dt.strftime('%s'))
        }, settings.SECRET_KEY, algorithm='HS512')

        refresh_token = base64.b64encode(bytes(user.email + ' ' + dtR.strftime('%s'), encoding='utf-8'))
        return access_token, refresh_token
    except:
        return HttpResponse('Creating tokens problem!')
