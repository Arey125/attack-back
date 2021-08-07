from flask import Flask, jsonify, request
from flask_cors import cross_origin
from state import State

app = Flask(__name__)
st = State()

@app.route("/")
@cross_origin()
def hello():
    return jsonify(
        st.data()
    )


@app.route("/set")
def set_size():
    st.set_size(
        int(request.args.get('size'))
    )
    return hello()


@app.route("/attack")
def set_attack():
    st.set_attack(
        request.args.get('name')
    )
    return hello()


@app.route("/solve/<solution_id>")
def solve(solution_id):
    st.set_solution(solution_id)
    return hello()


if __name__ == '__main__':
    app.run(host='0.0.0.0')
