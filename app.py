from flask import Flask, render_template, request, jsonify, make_response, redirect
from flask import jsonify, make_response


app = Flask(__name__)

#..............................................................................................................................#
# Eror 404 not found
@app.errorhandler(404)
def page_not_found(error):
    return render_template('error/404.html'), 404

@app.route("/error-403-access-denied")
def access_denited():
    return render_template('error/403.html')
#..............................................................................................................................#

#Users page
@app.route("/")
def home():
    username = request.cookies.get('username')
    return render_template('user/home.html', username=username)

# Admin page
@app.route("/admin")
def admin_page():
    # Kiểm tra cookie
    role = request.cookies.get('role')
    if role == 'admin':
        return render_template('admin/dashboard.html')
    else:
        return redirect("/error-403-access-denied")

#..............................................................................................................................#


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
@app.route("/login", methods=['POST'])
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