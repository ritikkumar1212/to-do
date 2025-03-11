from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)

class Routine(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    sub = db.Column(db.String(10), nullable = False)
    hr = db.Column(db.Integer,nullable = False)

with app.app_context():
    db.create_all()

@app.route('/routine',methods = ['GET'])
def get_list():
    subj = Routine.query.all()
    return jsonify([{'id':i.id,'sub':i.sub,'hr':i.hr}for i in subj])

@app.route('/routine/<int:sub_id>', methods = ['GET'])
def get_list_by_id(sub_id):
    subj = Routine.query.get(sub_id)
    if subj:
        return jsonify({'id':subj.id,'sub':subj.sub,'hr':subj.hr})
    
    return jsonify({"error":"id not found"})

@app.route('/routine',methods = ['POST'])
def creating_task():
    data = request.json
    new_sub = Routine(sub = data['sub'], hr = data['hr'])
    db.session.add(new_sub)
    db.session.commit()
    return jsonify({'id':new_sub.id,'sub':new_sub.sub,'hr':new_sub.hr})

@app.route('/routine/<path:sub_id>', methods = ['DELETE'])
def delete_task(sub_id):
    subj = Routine.query.get(sub_id)
    if not subj:
        return jsonify({'error':"ID NOT FOUND"})
    else:
        db.session.delete(subj)
        db.session.commit()
        return jsonify("record deleted successfully")
    

@app.route('/routine/<int:sub_id>',methods = ['PUT'])
def update_task(sub_id):
    subj = Routine.query.get(sub_id)
    if not subj:
        return jsonify({'error':'Invalid id'})
    else:
        data=request.json
        subj.sub = data['sub']
        subj.hr = data['hr']
        db.session.commit()
        return jsonify({'id':subj.id,'sub':subj.sub,'hr':subj.hr})


if __name__ == '__main__':
    app.run(debug=True)