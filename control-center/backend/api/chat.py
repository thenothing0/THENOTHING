import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..models.schemas import ChatRequest

router = APIRouter(prefix="/chat", tags=["chat"])
logger = logging.getLogger("cc.chat")

_history: list[dict] = []


@router.post("")
async def chat(req: ChatRequest):
    _history.extend([m.model_dump() for m in req.messages])
    return {
        "role": "assistant",
        "content": "Chat backend connected. Provider integration streaming will be wired in Phase 2.",
        "provider": req.provider_id,
        "model": req.model_id,
    }


@router.get("/history")
async def history(limit: int = 50):
    return _history[-limit:]


@router.delete("/history")
async def clear_history():
    _history.clear()
    return {"cleared": True}


@router.websocket("/ws")
async def chat_ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            await websocket.send_json({
                "type": "message",
                "role": "assistant",
                "content": f"Received: {msg.get('content', '')[:100]}",
                "streaming": False,
            })
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("ws error: %s", e)
