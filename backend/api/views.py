from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import RegistrationUserSerializer, LoginSerializer ,ProfileSerializer,QuestionSerializer,QuestionUpdateSerializer,EditProfileSerializer,SchoolOrCollegeSerializer,SubjectSerializer,ClassSemesterSerializer,TopicSerializer,TermSerializer,AnswerSerializer,CreditPointSerializer
from .models import RegistrationUser,Question,SchoolOrCollege,Subject,ClassSemester,Topic,Term,Answer,CreditPoint
from django.contrib.sessions.models import Session
from django.contrib.auth import login
import logging
from rest_framework.parsers import JSONParser
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
import traceback
from django.conf import settings
import os
from django.http import FileResponse

from django.http import HttpResponse

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def registration_view(request):
    if request.method == 'POST':
        serializer = RegistrationUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Print message to terminal
            print(f"New user registered: {user.username}, Category: {user.category}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    
    if serializer.is_valid():
        email_or_username = serializer.validated_data['email_or_username']
        password = serializer.validated_data['password']
        category = serializer.validated_data['category']  # Retrieve category
        
        user = authenticate(request, username=email_or_username, password=password)
        if user:
            if user.is_approved:
                # Log in the user
                login(request, user)
                
                # Store user email, category, and token in session
                request.session['user_email'] = user.email
                request.session['user_category'] = user.category
                request.session.save()
                
                # Create or retrieve token for the user
                token, _ = Token.objects.get_or_create(user=user)
                
                # Print session and user information to terminal
                session_key = request.session.session_key
                print("Session Data:", request.session.items())
                print("Session User ID:", request.session.get('user_email'))
                print("Session category:", request.session.get('user_category'))
                print("Session Key:", session_key)
                print("Token:", token.key)
                print(f"User logged in: {user.username}, Category: {user.category}")
                
                return Response({'token': token.key, 'message': 'Login successful'}, status=status.HTTP_200_OK)
            else:
                print("User not approved")  # Handle case where user is not approved
                return Response({'message': 'User not approved'}, status=status.HTTP_403_FORBIDDEN)
        else:
            print("Invalid credentials")  # Handle case where authentication fails
            return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        print("Invalid data provided")  # Handle case where serializer validation fails
        return Response({'message': 'Invalid data provided'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def approve_user(request, user_id):
    try:
        user = get_object_or_404(RegistrationUser, id=user_id)
        
        # Check if the requesting user has the permission to approve users
        if not request.user.has_perm('yourapp.can_approve_user'):
            return Response({'message': 'You do not have permission to approve users'}, status=status.HTTP_403_FORBIDDEN)
        
        # Set the is_approved field to True
        user.is_approved = True
        user.save()
        
        return Response({'message': 'User approved successfully'}, status=status.HTTP_200_OK)
    
    except RegistrationUser.DoesNotExist:
        return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    except Exception as e:
        logger.exception("An error occurred while approving the user")
        return Response({'message': 'Internal Server Error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reject_user(request, user_id):
    try:
        user = get_object_or_404(RegistrationUser, id=user_id)
        user.delete()  # Assuming you want to delete the user upon rejection
        return Response({'message': 'User rejected successfully'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': 'Failed to reject user'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def profile_view(request):
    try:
        user = request.user  # Retrieve authenticated user
        
        # Serialize the user profile data
        serializer = ProfileSerializer(user)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        print("Error:", e)
        return Response({'message': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def edit_profile(request):
    try:
        user = request.user
        serializer = EditProfileSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'message': 'Error updating profile'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def user_list(request):
    try:
        users = RegistrationUser.objects.all()
        serializer = RegistrationUserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)
    except Exception as e:
        print(f"Error fetching user data: {e}")
        return JsonResponse({'error': 'Failed to fetch user data'}, status=500)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_category(request):
    if request.method == 'POST':
        try:
            # Get email from request data
            email = request.POST.get('email')
            
            # Retrieve user based on email
            user = RegistrationUser.objects.get(email=email)
            
            # Get user's category
            user_category = user.category
            
            # Return user's category in the response
            return JsonResponse({'category': user_category}, status=200)
        except RegistrationUser.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    

@api_view(['POST'])
@permission_classes([AllowAny])
def add_question(request):
    if request.method == 'POST':
        serializer = QuestionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print("Validation errors:", serializer.errors)  # Print validation errors to terminal
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def get_uploaded_questions(request):
    if request.method == 'GET':
        questions = Question.objects.all()
        serialized_data = []

        for question in questions:
            status = False
            answers = Answer.objects.filter(question_id=question.id, status=True)
            if answers.exists():
                status = True
            serialized_data.append({
                'id': question.id,
                'subject': question.subject.name,
                'status': status
            })

        return Response(serialized_data)

    elif request.method == 'POST':
        serializer = QuestionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_question_details(request):
    if request.method == 'GET':
        questions = Question.objects.all()
        serializer = QuestionSerializer(questions, many=True)
        return Response(serializer.data)    

@api_view(['GET'])
@permission_classes([AllowAny])
def get_pdf(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    file_path = os.path.join(settings.MEDIA_ROOT, str(question.file))
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/pdf')
        response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
        return response    

@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_question(request, question_id):
    if request.method == 'DELETE':
        try:
            question = Question.objects.get(pk=question_id)
        except Question.DoesNotExist:
            return Response({"error": "Question not found"}, status=status.HTTP_404_NOT_FOUND)    
        question.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
@api_view(['PUT'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def edit_question(request, question_id):
    try:
        question = Question.objects.get(pk=question_id)
    except Question.DoesNotExist:
        return Response({"error": "Question not found"}, status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'PUT':
        serializer = QuestionUpdateSerializer(question, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # Log validation errors for debugging
            print("Validation Errors:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def school_or_college_list_create(request):
    if request.method == 'GET':
        schools_or_colleges = SchoolOrCollege.objects.all()
        serializer = SchoolOrCollegeSerializer(schools_or_colleges, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = SchoolOrCollegeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['DELETE'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def school_or_college_delete(request, pk):
    try:
        school_or_college = SchoolOrCollege.objects.get(pk=pk)
    except SchoolOrCollege.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        school_or_college.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
@api_view(['POST','GET'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def add_subject(request):
    if request.method == 'GET':
        subjects = Subject.objects.all()
        serializer = SubjectSerializer(subjects, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = SubjectSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)       
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['DELETE'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def delete_subject(request, subject_id):
    try:
        subject = Subject.objects.get(id=subject_id)
    except Subject.DoesNotExist:
        return Response({"error": "Subject does not exist"}, status=status.HTTP_404_NOT_FOUND)
    
    subject.delete()
    return Response({"message": "Subject deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


@api_view(['POST', 'GET'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def add_class_semester(request):
    if request.method == 'GET':
        class_semesters = ClassSemester.objects.all()
        serializer = ClassSemesterSerializer(class_semesters, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = ClassSemesterSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['DELETE'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def delete_class_semester(request, class_semester_id):
    try:
        class_semester = ClassSemester.objects.get(id=class_semester_id)
    except ClassSemester.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        class_semester.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
@api_view(['GET'])
@permission_classes([AllowAny])
def get_schools_or_colleges_names(request):
    schools_or_colleges = SchoolOrCollege.objects.all()
    serializer = SchoolOrCollegeSerializer(schools_or_colleges, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_subjects_names(request):
    subjects = Subject.objects.all()
    serializer = SubjectSerializer(subjects, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_class_semesters_names(request):
    class_semesters = ClassSemester.objects.all()
    serializer = ClassSemesterSerializer(class_semesters, many=True)
    return Response(serializer.data)

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def topic_list(request):
    if request.method == 'GET':
        topics = Topic.objects.all()
        serializer = TopicSerializer(topics, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = TopicSerializer(data=request.data)
        try:
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                print(serializer.errors)  # Print actual errors to the console
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"An error occurred: {e}")
            error_message = {
                "error": "Failed to create topic",
                "details": serializer.errors
            }
            return Response(error_message, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def term_list_create(request):
    if request.method == 'GET':
        terms = Term.objects.all()
        serializer = TermSerializer(terms, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = TermSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print(serializer.errors)  # Print the actual error
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([AllowAny])
@permission_classes([IsAuthenticated])
def term_delete(request, pk):
    try:
        term = Term.objects.get(pk=pk)
    except Term.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        term.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
@api_view(['GET'])
@permission_classes([AllowAny])
def get_term_name(request):
    terms = Term.objects.all()
    serializer = TermSerializer(terms, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_answer(request, question_id):
    try:
        # Retrieve the authenticated user's name
        name = request.user.name  # Fetching the username of the authenticated user

        # Retrieve the question object

        question = get_object_or_404(Question, id=question_id)

        # Check if the request contains a file
        if 'pdfFile' not in request.FILES:
            return Response({"error": "PDF file is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Create a new Answer object
        answer = Answer(question=question, name=name)
        
        # Save the uploaded file to the answer object
        answer.pdf_file = request.FILES['pdfFile']
        
        # Save the answer object
        answer.save()

        # Serialize the answer object
        serializer = AnswerSerializer(answer)

        # Return the serialized answer object with a 201 Created status
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    except Exception as e:
        # Return an error response with a 500 Internal Server Error status
        return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_answers(request, question_id):
    if request.method == 'GET':
        answers = Answer.objects.filter(question=question_id)
        serializer = AnswerSerializer(answers, many=True)
        return JsonResponse(serializer.data, safe=False)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_pdf_answer(request, answer_id):
    try:
        answer = get_object_or_404(Answer, pk=answer_id)
        file_path = os.path.join(settings.MEDIA_ROOT, str(answer.pdf_file))
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/pdf')
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response
    except Exception as e:
        return HttpResponse(str(e), status=500)
    



@api_view(['GET'])
@permission_classes([AllowAny])
def get_pdf_question(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    file_path = os.path.join(settings.MEDIA_ROOT, str(question.file))
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/pdf')
        response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
        return response




@api_view(['PUT'])
@permission_classes([AllowAny])
def toggle_review_status(request, question_id, answer_id):
    try:
        # Get the answer object based on its ID
        answer = get_object_or_404(Answer, id=answer_id)
        
        # Ensure that the answer belongs to the specified question
        if answer.question.id != question_id:
            error_msg = f"Answer with ID {answer_id} does not belong to question with ID {question_id}."
            return Response({'message': error_msg}, status=status.HTTP_404_NOT_FOUND)
        
        # Toggle the review status of the answer
        answer.status = not answer.status
        answer.save()
        
        return Response({'message': 'Review status updated successfully'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['PUT'])
@permission_classes([AllowAny])
def toggle_answer_status(request, question_id):
    try:
        question = Question.objects.get(id=question_id)
        question.status = not question.status
        question.save()
        return Response({'message': 'Answer status toggled successfully.'})
    except Question.DoesNotExist:
        return Response({'error': 'Question not found.'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)
    

@api_view(['GET'])
@permission_classes([AllowAny])
def get_credit_points(request):
    credit_points = CreditPoint.objects.all()
    serializer = CreditPointSerializer(credit_points, many=True)
    return JsonResponse(serializer.data, safe=False)

@api_view(['PUT'])
@permission_classes([AllowAny])
def add_credit_point(request):
    data = request.data
    serializer = CreditPointSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return JsonResponse(serializer.data, status=201)
    return JsonResponse(serializer.errors, status=400)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_questions_with_answer_status(request):
    if request.method == 'GET':
        questions = Question.objects.all()
        data = []
        for question in questions:
            answers = Answer.objects.filter(question_id=question.id)
            if answers.exists():
                status = answers[0].status  # Assuming you want to use the status of the first answer
            else:
                status = False
            if status:  # If status is True, meaning an answer exists with status True
                serializer = QuestionSerializer(question)
                serialized_question = serializer.data
                serialized_question['status'] = status
                data.append(serialized_question)
        return Response(data)