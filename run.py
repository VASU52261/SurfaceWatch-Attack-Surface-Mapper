from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  ATSM Website running!")
    print("  Open: http://localhost:5000")
    print("="*50 + "\n")
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
