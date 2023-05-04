from uuid import uuid4

from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from django.contrib.auth.password_validation import (
    validate_password as original_pwd_validate,
)
from rest_framework import serializers
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer as OriginalObtainPairSerializer,
)

from rest_framework.validators import UniqueValidator

from .models import Room, User

# Get Token을 위한 Serializer
class TokenObtainPairSerializer(OriginalObtainPairSerializer):
    """
    Custom Token pair generator, Added full_name field to tokens to access it on a frontend
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token

# 회원가입을 할 때 토큰을 생성하는 Serializer
class RegisterTokenSerializer(serializers.ModelSerializer):
    """
    User registers through this serializer an receive tokens for authentication
    """

    tokens = serializers.SerializerMethodField("getting_token", read_only=True)

    def getting_token(self, user):
        refresh = TokenObtainPairSerializer.get_token(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

    class Meta:
        model = User
        fields = ("username", "email", "nickname", "password", "tokens")

    def create(self, validated_data):
        instance = self.Meta.model.objects.create_user(**validated_data)
        return instance

class PasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required = True)
    
    # Validates the password with django password validation
    def validate_password(self, pwd):
        
        import re

        pattern = re.compile(r'^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{8,}$')

        if not pattern.match(pwd):
            return False
            
# 로그인 Serializer
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required = True)
    # write_only를 통해서 서버 -> 클라이언트 방향의 직렬화를 방지하여 보안 UP
    password = serializers.CharField(required = True)

    def validate(self, data):
        user = authenticate(**data)
        if user:
            token = Token.objects.get(user=user)
            return {"token":token, "User":User.objects.get(username=user.username)}         
        raise serializers.ValidationError(
            {"error": "Unable to log in"}
        )

# username 필드가 유일하다는 것을 확인하는 Serailizer
class UsernameUniqueCheckSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True, min_length=3, max_length=30, validators=[UniqueValidator(queryset=User.objects.all())])

    class Meta:
        model = User
        fields = ('username',)
        
# nickname 필드가 유일하다는 것을 확인하는 Serailizer
class EmailUniqueCheckSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True, min_length=3, max_length=30, validators=[UniqueValidator(queryset=User.objects.all())])

    class Meta:
        model = User
        fields = ('email',)

class RoomSerializer(serializers.ModelSerializer):

    """
    Room Serialiser
    """

    room_id = serializers.SerializerMethodField()
    created_on = serializers.DateTimeField(
        format="%a %I:%M %p, %d %b %Y", required=False
    )

    class Meta:
        model = Room
        fields = [
            "id",
            "user",
            "title",
            "description",
            "type_of",
            "created_on",
            "room_id",
        ]

    # Generate room id
    def get_room_id(self, obj):
        if obj.type_of == "IO":
            return "room" + str(uuid4().hex)
        return "room" + str(obj.id)
