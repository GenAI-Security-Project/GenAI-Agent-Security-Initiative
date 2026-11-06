import streamlit as st
import promptinjection
import os

from upload_path import UploadPathError, safe_cv_path

if 'app' not in st.session_state:
    st.session_state.app = promptinjection.build_graph()

if 'messages' not in st.session_state:
    st.session_state.messages = []

st.title("CV reviewer chatbot")

api_key = st.sidebar.text_input("Enter your GROQ API key", type="password")

if api_key:
    os.environ["GROQ_API_KEY"] = api_key
    st.sidebar.success("GROQ_API_KEY has been set.")

UPLOAD_FOLDER = "cvs"

pdf_file = st.sidebar.file_uploader("Upload a PDF CV", type=["pdf"])

if pdf_file:
    try:
        file_path = safe_cv_path(UPLOAD_FOLDER, pdf_file.name)
    except UploadPathError as exc:
        st.sidebar.error(str(exc))
    else:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "wb") as handle:
            handle.write(pdf_file.getbuffer())
        st.sidebar.success("CV successfully uploaded")

for message in st.session_state["messages"]:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if prompt := st.chat_input("Enter prompt here.."):
    st.session_state["messages"].append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    result = st.session_state.app.invoke({"prompt": prompt})
    assistant_reply = result.get("final_answer", "No response generated.")

    with st.chat_message("assistant"):
        st.markdown(assistant_reply)
    st.session_state["messages"].append({"role": "assistant", "content": assistant_reply})
