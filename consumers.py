import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from urllib.parse import parse_qs

@database_sync_to_async
def get_user_role(session_id, user, guest_id):
    try:
        from transformations.models import CollaborationSession, SessionParticipant
        session = CollaborationSession.objects.get(id=session_id)
        if user and user.is_authenticated and session.host == user:
            return 'approved', 'editor'
        
        participant = None
        if user and user.is_authenticated:
            participant = SessionParticipant.objects.filter(session=session, user=user).first()
        elif guest_id:
            participant = SessionParticipant.objects.filter(session=session, guest_id=guest_id).first()
        
        if participant:
            return participant.status, participant.role
        return None, None
    except Exception:
        return None, None

class CollabConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.session_id = self.scope['url_route']['kwargs']['session_id']
        self.room_group_name = f'collab_{self.session_id}'
        
        query_string = self.scope.get('query_string', b'').decode('utf-8')
        query_params = parse_qs(query_string)
        guest_id = query_params.get('guest_id', [None])[0]
        
        self.participant_status, self.participant_role = await get_user_role(
            self.session_id, self.scope.get('user'), guest_id
        )

        if self.participant_status in ['kicked', None]:
            await self.close()
            return

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    # Receive message from WebSocket (Yjs uses raw bytes primarily)
    async def receive(self, text_data=None, bytes_data=None):
        
        # Zero-Trust Security Enforcement
        if self.participant_status != 'approved':
            return # Waitlisted users cannot send/receive operational transformations
            
        if self.participant_role == 'viewer' and bytes_data:
            # y-protocols byte filtering:
            # 0 -> Sync message. Next byte: 0=SyncStep1, 1=SyncStep2, 2=Update
            # 1 -> Awareness message.
            if len(bytes_data) >= 2 and bytes_data[0] == 0 and bytes_data[1] in (1, 2):
                # Drop document mutation vectors from Viewers. They can only send Awareness/SyncStep1
                return
        # Broadcast the message to the room group
        if bytes_data is not None:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'yjs_message',
                    'bytes_data': bytes_data,
                    'sender_channel': self.channel_name
                }
            )
        elif text_data is not None:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'yjs_message',
                    'text_data': text_data,
                    'sender_channel': self.channel_name
                }
            )

    async def yjs_message(self, event):
        # Do not bounce messages back to the sender
        if event.get('sender_channel') == self.channel_name:
            return

        # Send message to WebSocket
        if 'bytes_data' in event:
            await self.send(bytes_data=event['bytes_data'])
        elif 'text_data' in event:
            await self.send(text_data=event['text_data'])

    async def role_update(self, event):
        target_user_id = event.get('target_user_id')
        target_guest_id = event.get('target_guest_id')
        new_role = event.get('new_role')

        my_user = self.scope.get('user')
        query_string = self.scope.get('query_string', b'').decode('utf-8')
        from urllib.parse import parse_qs
        my_guest = parse_qs(query_string).get('guest_id', [None])[0]

        is_target = False
        if my_user and my_user.is_authenticated and target_user_id:
            if str(my_user.id) == str(target_user_id):
                is_target = True
        elif my_guest and target_guest_id:
            if str(my_guest) == str(target_guest_id):
                is_target = True

        if is_target:
            self.participant_role = new_role
            await self.send(text_data=json.dumps({
                'type': 'role_update',
                'role': new_role
            }))

    async def role_changed(self, event):
        target_user_id = event.get('target_user_id')
        target_guest_id = event.get('target_guest_id')
        new_role = event.get('new_role')
        
        my_user = self.scope.get('user')
        query_string = self.scope.get('query_string', b'').decode('utf-8')
        from urllib.parse import parse_qs
        my_guest = parse_qs(query_string).get('guest_id', [None])[0]
        
        is_target = False
        if my_user and my_user.is_authenticated and target_user_id:
            if str(my_user.id) == str(target_user_id):
                is_target = True
        elif my_guest and target_guest_id:
            if str(my_guest) == str(target_guest_id):
                is_target = True
        
        if is_target:
            self.participant_role = new_role
            await self.send(text_data=json.dumps({
                'type': 'role_update',
                'role': new_role
            }))
        else:
            await self.send(text_data=json.dumps({
                'type': 'role_changed_broadcast',
                'target_user_id': target_user_id,
                'target_guest_id': target_guest_id,
                'new_role': new_role
            }))

    async def waitlist_notification(self, event):
        # Only send to the host
        if self.scope.get('user') and self.scope['user'].is_authenticated:
            from transformations.models import CollaborationSession
            try:
                session = CollaborationSession.objects.get(id=self.session_id)
                if session.host == self.scope['user']:
                    await self.send(text_data=json.dumps({
                        'type': 'waitlist_notification',
                        'participant_name': event.get('participant_name'),
                        'participant_id': event.get('participant_id')
                    }))
            except Exception:
                pass

    async def session_ended(self, event):
        session_id = event.get('session_id')
        message = event.get('message', 'The session has been ended by the host.')
        
        await self.send(text_data=json.dumps({
            'type': 'session_ended',
            'session_id': session_id,
            'message': message
        }))
