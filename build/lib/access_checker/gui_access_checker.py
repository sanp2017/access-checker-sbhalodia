from flask import Flask, render_template, request
from access_checker.acl_parser_bk import cisco_acl
from flask_bootstrap import Bootstrap


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '3a71443a5943bebe9d555793034568e9'
    Bootstrap(app)

    @app.route("/")
    def access_check():
        return render_template('access_page.html')

    @app.route("/result", methods=['POST', 'GET'])
    def result():
        if request.method == 'POST':
            tmp = request.form
            a = cisco_acl(tmp['src_ip'], tmp['dst_ip'], tmp['src_port'], tmp['dst_port'], tmp['protocol'],
                          tmp['input_acl'])
            return render_template("result.html", a=a)
    app.run(debug=True)


if __name__ == '__main__':
    create_app()

