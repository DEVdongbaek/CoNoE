from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets, generics
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView as OriginalObtainPairView

from .models import Room 
from .serializers import (
    RoomSerializer,
    TokenObtainPairSerializer,
    RegisterTokenSerializer,
    EmailUniqueCheckSerializer,
    UsernameUniqueCheckSerializer,
    LoginSerializer,
    PasswordSerializer
)


class TokenObtainPairView(OriginalObtainPairView):
    """
    Replacing old 'serializer_class' with modified serializer class
    """

    serializer_class = TokenObtainPairSerializer

# 회원가입 View
class RegisterAndObtainTokenView(APIView):

    """
    Register user. Only Post method is allowed
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, format="json"):
        
        # username 중복 체크
        id_serializer = UsernameUniqueCheckSerializer(data=request.data)
        
        # email 중복 체크
        email_serializer = EmailUniqueCheckSerializer(data=request.data)
           
        pwd_serializer = PasswordSerializer(data=request.data) 
              
        if pwd_serializer.validate_password(pwd=request.data.get("password")) == False:    
            return Response("비밀번호는 영어와 숫자를 포함해야 하며, 8글자 이상이어야 합니다.", status=status.HTTP_400_BAD_REQUEST)
              
              
        # ID 유효성 검증에 통과 했을 때, ID가 중복되지 않았을 때 
        if id_serializer.is_valid():
            # email 유효성 검증에 통과 했을 때, nickname이 중복되지 않았을 때 
            if email_serializer.is_valid():
                serializer = RegisterTokenSerializer(data=request.data)                        
                if serializer.is_valid(): 
                    user = serializer.save() 
                    if user:
                        json = serializer.data
                        return Response(json, status=status.HTTP_201_CREATED)
            
            # email 중복 되었을 때
            else:
                return Response("이미 존재하는 이메일입니다.", status=status.HTTP_400_BAD_REQUEST)

        # ID가 중복되었을 때 
        else:
            return Response("이미 존재하는 아이디입니다.", status=status.HTTP_400_BAD_REQUEST)

        return Response("오류가 발생하였습니다.", status=status.HTTP_400_BAD_REQUEST)


# 로그인 View
# 로그인하고, 유저에 맞는 토큰 가져오기
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    authentication_classes = [TokenAuthentication]
        
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            token_user = serializer.validated_data # LoginSerializer안의 validate()의 리턴값인 Token을 받아옴
            token = token_user["token"]
            user = token_user["User"]
            request.session['user'] = user.username
            return Response({"token": token.key, "user":user.data}, status=status.HTTP_200_OK)
        
        else:
            return Response("로그인을 실패 하였습니다.", status=status.HTTP_400_BAD_REQUEST)


class RoomViewSet(viewsets.ModelViewSet):
    """
    Rooms View
    """
    queryset = Room.objects.all().order_by("-created_on")
    serializer_class = RoomSerializer

    def get_queryset(self):

        # By default list of rooms return
        queryset = Room.objects.all().order_by("-created_on")

        # If search params is given then list matching the param is returned
        search = self.request.query_params.get("search", None)
        if search is not None:
            queryset = Room.objects.filter(title__icontains=search).order_by(
                "-created_on"
            )
        return queryset

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action == "list" or self.action == "retrieve":
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def destroy(self, request, pk=None):

        """
        Checks whether user requesting a delete of the room is the owner of the room or not
        """
        room = get_object_or_404(Room, id=pk)

        if room:
            authenticate_class = JWTAuthentication()
            user, _ = authenticate_class.authenticate(request)
            if user.id == room.user.id:
                room.delete()
            else:
                return Response(
                    {
                        "message": "Either you are not logged in or you are not the owner of this room to delete"
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        return Response({}, status=status.HTTP_204_NO_CONTENT)
