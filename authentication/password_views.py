"""Password endpoint, independent of optional login/upload dependencies."""
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.serializers import UpdatePasswordSerializer


class UpdatePassword(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        serializer = UpdatePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Password Changed"}, status=status.HTTP_200_OK)
