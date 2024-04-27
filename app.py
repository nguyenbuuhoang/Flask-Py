from flask import Flask, render_template, request
from flask import jsonify, make_response


app = Flask(__name__)

@app.route("/")
def about_page():
    # check cookie
    username = request.cookies.get('username')
    password = request.cookies.get('password')
    print('username:', username)
    print('password:', password)
    if username == 'admin' and password == 'admin':
        return render_template('dashboard.html')
    return render_template('login.html')


# sign_out
@app.route("/sign_out", methods=['POST'])
def sign_out():
    response = make_response(jsonify({'message': 'Sign out successful'}))
    response.set_cookie('username', '', expires=0)
    response.set_cookie('password', '', expires=0)
    return response


# set_caution
@app.route("/set_caution", methods=['POST'])
def set_caution():
    global water_caution_level
    if request.method == 'POST':
        data = request.json
        caution = data.get('water_level')
        print('caution:', caution)
        water_caution_level = int(caution)
        # save to 
        return jsonify({'message': 'Set caution successful'})
    else:
        return jsonify({'message': 'Method not allowed'})

# login
@app.route("/login_admin", methods=['POST'])
def login_admin():
    if request.method == 'POST':
        data = request.json  # Lấy dữ liệu gửi từ frontend dưới dạng JSON
        username = data.get('username')
        password = data.get('password')

        print('username:', username)
        print('password:', password)
        if username == 'admin' and password == 'admin':
            # save cookie
            response = make_response(jsonify({'message': 'Login successful', 'username': username}))
            response.set_cookie('username', username)
            response.set_cookie('password', password)
            return response
        else:
            return jsonify({'message': 'Login failed'})
    else:
        return jsonify({'message': 'Method not allowed'})
    
if __name__ == "__main__":
     app.run(debug=True)