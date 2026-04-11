import structlog #New comment
import os #Latest comment
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from users.models import OTPDevice
from .serializers import TransformationRequestSerializer, TransformationResultSerializer, TransformationRequestHistorySerializer, TransformationRequestCodeSerializer
from transformations.models import TransformationRequest, TransformationResult
from transformations.tasks import process_transformation_job
from engine.ai_layer import AIEngineRouter
import random
from datetime import timedelta
from django.utils import timezone

class IsOTPVerified(permissions.BasePermission):
    message = "You must verify your OTP before using this endpoint."
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        # Get or create device
        device, _ = OTPDevice.objects.get_or_create(user=request.user)
        return device.is_verified

class SendOTPView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        device, _ = OTPDevice.objects.get_or_create(user=request.user)
        code = device.generate_code()
        # Ensure email sends safely
        try:
            from django.conf import settings
            subject = "Wizard Code Bridge - Security Verification"
            body = f"""Your Wizard Code Bridge verification code is: {code}

WARNING: If you did not attempt to sign in, someone has accessed your account with your credentials. We strongly recommend you change your password immediately."""
            send_mail(
                subject,
                body,
                settings.DEFAULT_FROM_EMAIL,
                [request.user.email],
                fail_silently=True,
            )
        except Exception:
            pass # fallback if mail fails
        return Response({"message": "OTP sent successfully."}, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        code = request.data.get("code")
        if not code:
            return Response({"error": "Code is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            device = OTPDevice.objects.get(user=request.user)
            if device.code == code:
                device.is_verified = True
                device.save()
                return Response({"message": "Successfully verified!"}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid OTP code."}, status=status.HTTP_400_BAD_REQUEST)
        except OTPDevice.DoesNotExist:
            return Response({"error": "Device not found."}, status=status.HTTP_400_BAD_REQUEST)

class CheckEmailView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get("email", "").strip().lower()
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        User = get_user_model()
        exists = User.objects.filter(email__iexact=email).exists()
        
        if exists:
            return Response({"available": False, "message": "This email is already registered."}, status=status.HTTP_200_OK)
        return Response({"available": True, "message": "Email is available."}, status=status.HTTP_200_OK)

class TransformHistoryView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def get(self, request):
        jobs = TransformationRequest.objects.filter(user=request.user).order_by('-created_at')
        serializer = TransformationRequestHistorySerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TransformCodeView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def get(self, request, job_id):
        try:
            job = TransformationRequest.objects.get(id=job_id, user=request.user)
            serializer = TransformationRequestCodeSerializer(job)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except TransformationRequest.DoesNotExist:
            return Response({"error": "Job not found"}, status=status.HTTP_404_NOT_FOUND)


class CapabilitiesView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def get(self, request):
        from django.conf import settings
        from engine.execution_layer import ExecutionEngineRouter

        provider = ExecutionEngineRouter.get_provider()
        executable_languages = []
        try:
            executable_languages = list(provider.supported_languages())
        except Exception:
            executable_languages = []

        languages = [
            "python", "javascript", "typescript", "java", "c", "cpp", "csharp",
            "go", "rust", "php", "swift", "kotlin", "ruby", "dart", "scala",
            "r", "lua", "perl", "bash", "sql",
        ]

        frameworks = [
            "react", "vue", "angular", "svelte",
            "django", "express", "springboot", "fastapi", "flask", "laravel", "rails",
        ]

        modes = ["Translate", "Optimize", "Translate + Optimize", "Review"]

        monaco_lang_map = {
            "python": "python",
            "javascript": "javascript",
            "typescript": "typescript",
            "react": "javascript",
            "vue": "javascript",
            "angular": "typescript",
            "svelte": "javascript",
            "express": "javascript",
            "java": "java",
            "springboot": "java",
            "c": "c",
            "cpp": "cpp",
            "csharp": "csharp",
            "go": "go",
            "rust": "rust",
            "php": "php",
            "laravel": "php",
            "swift": "swift",
            "kotlin": "kotlin",
            "ruby": "ruby",
            "rails": "ruby",
            "dart": "dart",
            "scala": "scala",
            "r": "r",
            "lua": "lua",
            "perl": "perl",
            "bash": "shell",
            "sql": "sql",
            "django": "python",
            "fastapi": "python",
            "flask": "python",
        }

        return Response(
            {
                "modes": modes,
                "languages": languages,
                "frameworks": frameworks,
                "monaco_lang_map": monaco_lang_map,
                "execution_provider": getattr(provider, 'name', 'unknown'),
                "executable_languages": executable_languages,
                "max_user_code_lines": getattr(settings, 'MAX_USER_CODE_LINES', 1000),
            },
            status=status.HTTP_200_OK,
        )

class UserStatsView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def get(self, request):
        jobs = TransformationRequest.objects.filter(user=request.user)
        total_jobs = jobs.count()
        successful_jobs = jobs.filter(status='COMPLETED').count()
        
        # Aggregate languages using basic counter logic
        source_counts = {}
        target_counts = {}
        status_breakdown = {'COMPLETED': 0, 'FAILED': 0, 'PENDING': 0}
        daily_usage = {}
        total_lines = 0
        
        for job in jobs:
            src = job.source_language
            tgt = job.target_language
            source_counts[src] = source_counts.get(src, 0) + 1
            target_counts[tgt] = target_counts.get(tgt, 0) + 1
            
            # Status tracking
            if job.status in status_breakdown:
                status_breakdown[job.status] += 1
            else:
                status_breakdown[job.status] = 1
                
            # Date tracking
            date_str = job.created_at.strftime("%Y-%m-%d")
            daily_usage[date_str] = daily_usage.get(date_str, 0) + 1
            
            if job.raw_code:
                total_lines += len(job.raw_code.split('\n'))
            
        return Response({
            "total_transformations": total_jobs,
            "successful_transformations": successful_jobs,
            "total_lines": total_lines,
            "source_languages": source_counts,
            "target_languages": target_counts,
            "status_breakdown": status_breakdown,
            "daily_usage": daily_usage
        }, status=status.HTTP_200_OK)

logger = structlog.get_logger(__name__)

class TransformView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def post(self, request):
        # ---------------- Zero-Trust Security ----------------
        session_id = request.data.get('session_id')
        if session_id:
            try:
                from transformations.models import SessionParticipant
                participant = SessionParticipant.objects.get(session__id=session_id, user=request.user)
                if participant.role == 'viewer':
                    return Response({"error": "You are a Viewer in this session and cannot execute transformations."}, status=status.HTTP_403_FORBIDDEN)
            except Exception:
                pass
        # -----------------------------------------------------

        serializer = TransformationRequestSerializer(data=request.data)
        if serializer.is_valid():
            
            # AI Language Guard Intercept
            raw_code = serializer.validated_data.get('raw_code', '')
            source_language = serializer.validated_data.get('source_language', '')
            
            enable_validation = str(os.getenv('ENABLE_LANGUAGE_VALIDATION', 'False')).lower() == 'true'
            if enable_validation:
                ai_engine = AIEngineRouter.get_provider()
                validation_result = ai_engine.validate_language(raw_code, source_language)
                
                if not validation_result.get("is_match", True):
                    actual_lang = validation_result.get("actual_language", "Unknown")
                    # Loosen strictness: if the AI correctly identifies the language name despite returning is_match: False 
                    # (which happens when it detects syntax errors), we still let it pass.
                    if actual_lang.lower() != source_language.lower():
                        return Response({
                            "error": f"Language Mismatch Detected. You selected '{source_language}', but the AI identified the code as '{actual_lang}'. Please correct your selection and try again."
                        }, status=status.HTTP_400_BAD_REQUEST)
                
            transform_request = serializer.save(user=request.user)
            logger.info("transformation_requested", job_id=str(transform_request.id), user=request.user.id)
            
            # Queue Celery task
            tool_type = request.data.get('tool_type', 'studio')
            process_transformation_job.delay(str(transform_request.id), tool_type=tool_type)
            
            return Response({"job_id": transform_request.id, "status": "PENDING"}, status=status.HTTP_202_ACCEPTED)
        return Response({"error": "Invalid request.", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class TransformStatusView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def get(self, request, job_id):
        try:
            job = TransformationRequest.objects.get(id=job_id, user=request.user)
            
            response_data = {
                "job_id": job.id,
                "status": job.status,
            }

            if job.status == 'COMPLETED' and hasattr(job, 'result'):
                from .serializers import TransformationResultSerializer
                result_data = TransformationResultSerializer(job.result).data
                response_data["result"] = result_data
            elif job.status == 'FAILED' and hasattr(job, 'result'):
                response_data["error"] = job.result.error_message

            return Response(response_data, status=status.HTTP_200_OK)
        except TransformationRequest.DoesNotExist:
            return Response({"error": "Job not found"}, status=status.HTTP_404_NOT_FOUND)


class SandboxExecuteView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    # Strict allowlist for safety and to prevent this becoming a general proxy
    PISTON_LANG_MAP = {
        'python': {"language": 'python', "version": '3.10.0'},
        'javascript': {"language": 'javascript', "version": '18.15.0'},
        'java': {"language": 'java', "version": '15.0.2'},
        'c': {"language": 'c', "version": '10.2.0'},
        'cpp': {"language": 'c++', "version": '10.2.0'},
        'csharp': {"language": 'csharp', "version": '6.12.0'},
        'go': {"language": 'go', "version": '1.16.2'},
        'rust': {"language": 'rust', "version": '1.68.2'},
        'php': {"language": 'php', "version": '8.2.3'},
        'swift': {"language": 'swift', "version": '5.3.3'},
        'kotlin': {"language": 'kotlin', "version": '1.8.20'},
        'ruby': {"language": 'ruby', "version": '3.0.1'},
        'dart': {"language": 'dart', "version": '2.19.6'},
        'scala': {"language": 'scala', "version": '3.2.2'},
        'r': {"language": 'r', "version": '4.1.1'},
        'lua': {"language": 'lua', "version": '5.4.4'},
        'perl': {"language": 'perl', "version": '5.36.0'},
        'bash': {"language": 'bash', "version": '5.2.0'},
        'sql': {"language": 'sqlite3', "version": '3.36.0'},
    }

    FRAMEWORK_LIST = {'react', 'vue', 'angular', 'svelte', 'django', 'express', 'springboot', 'fastapi', 'flask', 'laravel', 'rails'}

    def post(self, request):
        # ---------------- Zero-Trust Security ----------------
        session_id = request.data.get('session_id')
        if session_id:
            try:
                from transformations.models import SessionParticipant
                participant = SessionParticipant.objects.get(session__id=session_id, user=request.user)
                if participant.role == 'viewer':
                    return Response({"error": "You are a Viewer in this session and cannot execute code."}, status=status.HTTP_403_FORBIDDEN)
            except Exception:
                pass
        # -----------------------------------------------------

        target_language = request.data.get('target_language')
        code = request.data.get('code', '')
        stdin = request.data.get('stdin', '')
        env_vars = request.data.get('env_vars')

        if not target_language:
            return Response({"error": "target_language is required"}, status=status.HTTP_400_BAD_REQUEST)

        target_language = str(target_language).lower().strip()
        if target_language in self.FRAMEWORK_LIST:
            return Response({"error": "Cannot execute framework code in Sandbox."}, status=status.HTTP_400_BAD_REQUEST)

        # Enforce the active execution provider's supported language list.
        # This keeps the API authoritative and allows switching providers via env without frontend changes.
        try:
            from engine.execution_layer import ExecutionEngineRouter
            provider = ExecutionEngineRouter.get_provider()
            provider_supported = set(provider.supported_languages() or [])
        except Exception:
            provider_supported = set()

        # Fallback to our historical allowlist if provider introspection fails.
        if not provider_supported:
            provider_supported = set(self.PISTON_LANG_MAP.keys())

        if target_language not in provider_supported:
            return Response({"error": f"Sandbox execution not supported for {target_language}"}, status=status.HTTP_400_BAD_REQUEST)

        if not code or not str(code).strip():
            return Response({"error": "code is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Guard: keep payloads small to avoid turning this into a bandwidth abuse vector
        code_str = str(code)
        if len(code_str) > 50_000:
            return Response({"error": "Code too large for sandbox execution."}, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        stdin_str = str(stdin or "")
        if len(stdin_str) > 10_000:
            return Response({"error": "stdin too large for sandbox execution."}, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        try:
            from engine.execution_layer import ExecutionEngineRouter
            provider = ExecutionEngineRouter.get_provider()
            data = provider.execute(target_language, code_str, stdin=stdin_str, env_vars=env_vars)

            if isinstance(data, dict) and data.get('error'):
                msg = str(data.get('error'))
                # Common case: Piston public endpoint is now whitelist-only
                if 'whitelist' in msg.lower() or 'white list' in msg.lower():
                    return Response({"error": msg}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
                if 'unable to reach piston' in msg.lower() or 'invalid response from piston' in msg.lower():
                    return Response({"error": msg}, status=status.HTTP_502_BAD_GATEWAY)
                return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)

            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            logger = structlog.get_logger(__name__)
            logger.exception("sandbox_execution_failed", error=str(e))
            return Response({"error": "Sandbox execution failed."}, status=status.HTTP_502_BAD_GATEWAY)

import zipfile
import io
from rest_framework.parsers import MultiPartParser

class TransformFileView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]
    parser_classes = [MultiPartParser]

    EXTENSION_MAP = {
        'python': 'py', 'django': 'py', 'fastapi': 'py', 'flask': 'py',
        'javascript': 'js', 'react': 'jsx', 'vue': 'vue', 'svelte': 'svelte', 'express': 'js',
        'typescript': 'ts', 'angular': 'ts',
        'java': 'java', 'springboot': 'java',
        'c': 'c', 'cpp': 'cpp', 'csharp': 'cs',
        'go': 'go', 'rust': 'rs', 'php': 'php', 'laravel': 'php',
        'swift': 'swift', 'kotlin': 'kt', 'ruby': 'rb', 'rails': 'rb',
        'dart': 'dart', 'scala': 'scala', 'r': 'r', 'lua': 'lua', 'perl': 'pl', 'bash': 'sh', 'sql': 'sql'
    }


    def post(self, request):
        uploaded_file = request.FILES.get('file')
        source_language = request.data.get('source_language')
        target_language = request.data.get('target_language')
        mode = request.data.get('mode')
        generate_tests = str(request.data.get('generate_tests')).lower() == 'true'

        if not uploaded_file or not source_language or not mode:
            return Response({"error": "Missing required fields."}, status=status.HTTP_400_BAD_REQUEST)

        file_ext = uploaded_file.name.split('.')[-1].lower()
        ai_engine = AIEngineRouter.get_provider()
        
        # Output zip buffer
        zip_buffer = io.BytesIO()

        if file_ext == 'zip':
            # Handle ZIP Archive
            try:
                with zipfile.ZipFile(uploaded_file, 'r') as zip_in:
                    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_out:
                        count = 0
                        for original_filename in zip_in.namelist():
                            if count >= 10:  # MVP Guard to prevent 429 TPM limits
                                break
                                
                            # Skip directories or massive files
                            if original_filename.endswith('/') or zip_in.getinfo(original_filename).file_size > 50000:
                                continue
                                
                            raw_code = zip_in.read(original_filename).decode('utf-8', errors='ignore')
                            if not raw_code.strip():
                                continue
                                
                            # AI Language Guard Intercept (only on the first valid file)
                            if count == 0:
                                enable_validation = str(os.getenv('ENABLE_LANGUAGE_VALIDATION', 'False')).lower() == 'true'
                                if enable_validation:
                                    validation_result = ai_engine.validate_language(raw_code, source_language)
                                    if not validation_result.get("is_match", True):
                                        actual_lang = validation_result.get("actual_language", "Unknown")
                                        if actual_lang.lower() != source_language.lower():
                                            return Response({
                                                "error": f"Language Mismatch inside ZIP ({original_filename}). You selected '{source_language}', but AI identified it as '{actual_lang}'."
                                            }, status=status.HTTP_400_BAD_REQUEST)

                            # Transform File
                            try:
                                res = ai_engine.transform(
                                    code=raw_code,
                                    ast_info={"notice": "Bulk File Translation MVP"},
                                    static_findings=[],
                                    source_language=source_language,
                                    target_language=target_language,
                                    mode=mode,
                                    generate_tests=generate_tests
                                )
                                
                                if "error" in res:
                                    logger.error("bulk_file_ai_error", error=res["error"], file=original_filename)
                                    continue
                                
                                translated_str = res.get("translated_code", "")
                                if translated_str:
                                    # Output file into zip retaining original structure
                                    ext_target = target_language if target_language else source_language
                                    mapped_ext = self.EXTENSION_MAP.get(ext_target.lower(), ext_target)
                                    
                                    name_base = ".".join(original_filename.split(".")[:-1])
                                    new_filename = f"{name_base}.{mapped_ext}"
                                    zip_out.writestr(new_filename, translated_str.encode('utf-8'))
                                    
                                    if generate_tests and res.get("unit_tests_code"):
                                        test_filename = f"{name_base}_test.{mapped_ext}"
                                        zip_out.writestr(test_filename, res["unit_tests_code"].encode('utf-8'))
                                        
                            except Exception as e:
                                logger.error("bulk_file_failed", error=str(e), file=original_filename)
                            
                            count += 1
            except zipfile.BadZipFile:
                return Response({"error": "Invalid ZIP file provided."}, status=status.HTTP_400_BAD_REQUEST)

        else:
            # Handle Single File
            raw_code = uploaded_file.read().decode('utf-8', errors='ignore')
            
            # AI Language Guard Intercept
            enable_validation = str(os.getenv('ENABLE_LANGUAGE_VALIDATION', 'False')).lower() == 'true'
            if enable_validation:
                validation_result = ai_engine.validate_language(raw_code, source_language)
                if not validation_result.get("is_match", True):
                    actual_lang = validation_result.get("actual_language", "Unknown")
                    if actual_lang.lower() != source_language.lower():
                        return Response({
                            "error": f"Language Mismatch. You selected '{source_language}', but AI identified it as '{actual_lang}'."
                        }, status=status.HTTP_400_BAD_REQUEST)

            try:
                res = ai_engine.transform(
                    code=raw_code,
                    ast_info={"notice": "Bulk File Translation MVP"},
                    static_findings=[],
                    source_language=source_language,
                    target_language=target_language,
                    mode=mode,
                    generate_tests=generate_tests
                )
                
                if "error" in res:
                    return Response({"error": res["error"]}, status=status.HTTP_400_BAD_REQUEST)
                
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_out:
                    translated_str = res.get("translated_code", "")
                    if translated_str:
                        ext_target = target_language if target_language else source_language
                        mapped_ext = self.EXTENSION_MAP.get(ext_target.lower(), ext_target)
                        
                        name_base = ".".join(uploaded_file.name.split(".")[:-1])
                        new_filename = f"{name_base}.{mapped_ext}"
                        zip_out.writestr(new_filename, translated_str.encode('utf-8'))
                        
                        if generate_tests and res.get("unit_tests_code"):
                            test_filename = f"{name_base}_test.{mapped_ext}"
                            zip_out.writestr(test_filename, res["unit_tests_code"].encode('utf-8'))
                            
            except Exception as e:
                return Response({"error": "Failed to translate file: " + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        zip_buffer.seek(0)
        from django.http import HttpResponse
        response = HttpResponse(zip_buffer, content_type='application/zip')
        response['Content-Disposition'] = 'attachment; filename="translated_project.zip"'
        return response

class CustomInstructionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from users.models import DeveloperProfile
        profile, _ = DeveloperProfile.objects.get_or_create(user=request.user)
        return Response({"custom_instructions": profile.custom_instructions}, status=status.HTTP_200_OK)

    def post(self, request):
        from users.models import DeveloperProfile
        instructions = request.data.get("custom_instructions", "")
        profile, _ = DeveloperProfile.objects.get_or_create(user=request.user)
        profile.custom_instructions = instructions
        profile.save()
        return Response({"status": "Instructions updated successfully."}, status=status.HTTP_200_OK)


from transformations.models import CollaborationSession, SessionParticipant
from .serializers import CollaborationSessionSerializer, CollaborationSessionListSerializer

class CollabCreateView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def post(self, request):
        mode = request.data.get('permission_mode', 'open')
        name = request.data.get('name', 'Collab Session')
        # Name defaults to Collab Session if empty string passed
        if not name or not str(name).strip():
            name = 'Collab Session'
            
        session = CollaborationSession.objects.create(host=request.user, permission_mode=mode, name=name)
        # Host is implicitly an approved editor
        SessionParticipant.objects.create(
            session=session,
            user=request.user,
            status='approved',
            role='host' # Specifically label the creator as "host" in the Participant table to simplify frontend detection
        )
        return Response({'session_id': session.id, 'name': session.name}, status=status.HTTP_201_CREATED)

class CollabJoinView(APIView):
    # AllowAny because anonymous / guest users might try to join a session using purely guest_id strings
    permission_classes = [AllowAny]

    def post(self, request, uuid_str):
        try:
            session = CollaborationSession.objects.get(id=uuid_str, is_active=True)
        except CollaborationSession.DoesNotExist:
            return Response({"error": "Session not found or inactive."}, status=status.HTTP_404_NOT_FOUND)
        
        # Determine User ID vs Guest ID
        user = request.user if request.user.is_authenticated else None
        guest_id = request.data.get('guest_id')

        # Identify existing participant
        if user:
            participant = SessionParticipant.objects.filter(session=session, user=user).first()
        elif guest_id:
            participant = SessionParticipant.objects.filter(session=session, guest_id=guest_id).first()
        else:
            return Response({"error": "Authentication or guest_id required."}, status=status.HTTP_400_BAD_REQUEST)

        # Hosts are immune
        if user and session.host == user:
            return Response({'status': 'approved', 'role': 'host', 'name': session.name}, status=status.HTTP_200_OK)

        # Create new participant if missing
        if not participant:
            if session.permission_mode == 'approval_required':
                participant = SessionParticipant.objects.create(
                    session=session, user=user, guest_id=guest_id, status='waitlist', role='viewer'
                )
                # Notify host about waitlist request via WebSocket
                try:
                    from channels.layers import get_channel_layer
                    from asgiref.sync import async_to_sync
                    channel_layer = get_channel_layer()
                    async_to_sync(channel_layer.group_send)(
                        f"collab_{uuid_str}",
                        {
                            "type": "waitlist_notification",
                            "participant_name": user.username if user else f"Guest_{guest_id[:6]}",
                            "participant_id": str(participant.id)
                        }
                    )
                except Exception:
                    pass  # WebSocket notification is best-effort
            else:
                default_role = 'viewer' if session.permission_mode == 'view_only' else 'editor'
                participant = SessionParticipant.objects.create(
                    session=session, user=user, guest_id=guest_id, status='approved', role=default_role
                )
        
        if participant.status == 'kicked':
            return Response({"error": "You have been blocked from this session."}, status=status.HTTP_403_FORBIDDEN)
            
        return Response({'status': participant.status, 'role': participant.role, 'name': session.name}, status=status.HTTP_200_OK)

class CollabLeaveView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uuid_str):
        user = request.user if request.user.is_authenticated else None
        guest_id = request.data.get('guest_id')
        
        try:
            if user:
                SessionParticipant.objects.filter(session__id=uuid_str, user=user).delete()
            elif guest_id:
                SessionParticipant.objects.filter(session__id=uuid_str, guest_id=guest_id).delete()
        except:
            pass
            
        return Response({"message": "Left session."}, status=status.HTTP_200_OK)

class CollabManageView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, uuid_str):
        try:
            session = CollaborationSession.objects.get(id=uuid_str, host=request.user)
        except CollaborationSession.DoesNotExist:
            return Response({"error": "Not your session."}, status=status.HTTP_403_FORBIDDEN)
        
        action = request.data.get('action')
        target_participant_id = request.data.get('participant_id')

        if action == 'end_session':
            end_message = request.data.get('message', 'The session has been ended by the host.')
            session.is_active = False
            session.save()
            
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"collab_{uuid_str}",
                {
                    "type": "session_ended",
                    "message": end_message,
                    "session_id": str(uuid_str)
                }
            )
            return Response({"message": "Session ended."}, status=status.HTTP_200_OK)
            
        elif action == 'change_mode':
            mode = request.data.get('mode')
            if mode in [c[0] for c in CollaborationSession.PERMISSION_CHOICES]:
                session.permission_mode = mode
                session.save()
                return Response({"message": f"Mode changed to {mode}."}, status=status.HTTP_200_OK)
        
        # User Specific Actions
        try:
            participant = SessionParticipant.objects.get(id=target_participant_id, session=session)
        except SessionParticipant.DoesNotExist:
            return Response({"error": "Target participant not found."}, status=status.HTTP_400_BAD_REQUEST)

        if action == 'approve':
            participant.status = 'approved'
            participant.save()
        elif action == 'kick':
            participant.status = 'kicked'
            participant.save()
        elif action == 'unblock':
            participant.status = 'approved'
            participant.role = 'viewer'
            participant.save()

        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        
        if action in ['approve', 'kick', 'unblock']:
            async_to_sync(channel_layer.group_send)(
                f"collab_{uuid_str}",
                {
                    "type": "role_update",
                    "target_user_id": str(participant.user.id) if participant.user else None,
                    "target_guest_id": str(participant.guest_id) if participant.guest_id else None,
                    "new_role": participant.role if action == 'approve' else ('kicked' if action == 'kick' else 'viewer')
                }
            )
            
        return Response({"message": f"Action {action} applied."}, status=status.HTTP_200_OK)

class CollabRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, uuid_str):
        try:
            session = CollaborationSession.objects.get(id=uuid_str, host=request.user)
            participant = SessionParticipant.objects.get(id=request.data.get('participant_id'), session=session)
        except:
            return Response({"error": "Invalid permission."}, status=status.HTTP_403_FORBIDDEN)
            
        role = request.data.get('role')
        if role in ['editor', 'viewer']:
            old_role = participant.role
            participant.role = role
            participant.save()

            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            
            # Broadcast role change to ALL participants (not just target)
            async_to_sync(channel_layer.group_send)(
                f"collab_{uuid_str}",
                {
                    "type": "role_changed",
                    "target_user_id": str(participant.user.id) if participant.user else None,
                    "target_guest_id": str(participant.guest_id) if participant.guest_id else None,
                    "new_role": role,
                    "session_id": str(uuid_str)
                }
            )

            return Response({"message": f"Assigned role: {role}."}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid role."}, status=status.HTTP_400_BAD_REQUEST)

class CollabListView(APIView):
    permission_classes = [IsAuthenticated, IsOTPVerified]

    def get(self, request):
        from django.db.models import Count
        # Fetch all ACTIVE sessions where the user is a participant
        participants_data = SessionParticipant.objects.filter(
            user=request.user, session__is_active=True
        ).select_related('session', 'session__host').annotate(
            participants_count=Count('session__participants')
        )
        serializer = CollaborationSessionListSerializer(participants_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CollabSessionDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, uuid_str):
        try:
            session = CollaborationSession.objects.get(id=uuid_str, host=request.user)
            serializer = CollaborationSessionSerializer(session)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except CollaborationSession.DoesNotExist:
            return Response({"error": "Session absent or not host."}, status=status.HTTP_403_FORBIDDEN)

class CollabHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, uuid_str):
        jobs = TransformationRequest.objects.filter(session__id=uuid_str).order_by('-created_at')
        serializer = TransformationRequestHistorySerializer(jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DownloadCodeView(APIView):
    permission_classes = [IsAuthenticated]
    
    LANGUAGE_EXTENSIONS = {
        'python': 'py',
        'javascript': 'js',
        'java': 'java',
        'c': 'c',
        'cpp': 'cpp',
        'csharp': 'cs',
        'go': 'go',
        'rust': 'rs',
        'ruby': 'rb',
        'php': 'php',
        'swift': 'swift',
        'kotlin': 'kt',
        'typescript': 'ts',
        'html': 'html',
        'css': 'css',
        'sql': 'sql',
        'shell': 'sh',
        'json': 'json',
        'xml': 'xml',
        'yaml': 'yaml',
    }

    def post(self, request):
        code = request.data.get('code', '')
        language = request.data.get('language', '').lower()
        filename = request.data.get('filename', '')
        
        if not code:
            return Response({'error': 'No code provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        extension = self.LANGUAGE_EXTENSIONS.get(language, 'txt')
        
        if filename:
            if not filename.endswith(f'.{extension}'):
                filename = f'{filename}.{extension}'
        else:
            filename = f'code.{extension}'
        
        response = HttpResponse(code, content_type='text/plain')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        user = request.user
        username = request.data.get('username', '')
        
        if username != user.username:
            return Response(
                {'error': 'Username does not match'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Delete user and all related data
        user.delete()
        
        return Response({'message': 'Account deleted successfully'})
