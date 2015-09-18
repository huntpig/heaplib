from flask import Flask, url_for, request, render_template

app = Flask(__name__)

"""
Exception class that is used by this Flask App.
"""
class HeaplibFrontendException(Exception):
    pass

"""
Views that correspond to various URLs in this Flask app.
"""

@app.route("/hello/")
@app.route("/hello/<name>")
def hello(name=None):
    return render_template('hello.html', name=name)

@app.route("/dlmalloc_unlink", methods=['GET', 'POST'])
def dlmalloc_unlink_method():
    if request.method == "GET":
        t = "dlmalloc unlink() method"
        return render_template("unlink_dlmalloc.html", title=t, heading=t,
                               action_link_1=url_for('dlmalloc_unlink_sd'),
                               action_link_2=url_for('dlmalloc_unlink_method'))
    elif request.method == "POST":
        payload = dlmalloc_unlink(request)
        t = "Dlmalloc unlink payload"
        return render_template("payload.html", title=t, heading=t,
                               payload=payload)

@app.route("/dlmalloc_unlink_sd", methods=['GET', 'POST'])
def dlmalloc_unlink_sd():
    if request.method == "GET":
        return "Hmmm, a GET?"
    elif request.method == "POST":
        t = "dlmalloc unlink() payload options"
        extract_stack_dump(request)
        chunk_to_overflow_into = generate_table("chunk_to_overflow_into")
        data_that_overflows = generate_table("data_that_overflows")
        end_point_data_after_C = generate_table("end_point_data_after_C")
        return render_template("unlink_dlmalloc_qns.html", title=t, heading=t,
                               chunk_to_overflow_into=chunk_to_overflow_into,
                               data_that_overflows=data_that_overflows,
                               end_point_data_after_C=end_point_data_after_C,
                               action_link_1=url_for('dlmalloc_unlink_sd_process'))

@app.route("/dlmalloc_unlink_sd_process", methods=['GET', 'POST'])
def dlmalloc_unlink_sd_process():
    if request.method == "GET":
        return "Hmm a GET for this page?"
    elif request.method == "POST":
        t = "Dlmalloc unlink payload"
        payload = process_dlmalloc_unlink_sd(request)
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


"""
Utility functions used by this Flask application.
"""

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

def process_dlmalloc_unlink_sd(request):
    payload = """
    prev = %s
    post = %s
    (PREV_SIZE_C, SIZE_C) = pack(%s), pack(%s)
    """
    for key in ['chunk_to_overflow_into', 'data_that_overflows', 'end_point_data_after_C',
                'address_to_overwrite', 'value_to_overwrite', 'pre_presets', 'post_presets',
                'bits']:
        if key not in request.form:
            raise HeaplibFrontendException("Parameter '%s' not found in request object." % key)

    chunk_to_overflow_into = int(request.form['chunk_to_overflow_into'].split(":")[0], 16)
    data_that_overflows = int(request.form['data_that_overflows'].split(":")[0], 16)
    end_point_data_after_C = int(request.form['end_point_data_after_C'].split(":")[0], 16)
    hpc = HeapPayloadCrafter("dlmalloc",
                             int(request.form['address_to_overwrite'], 16),
                             int(request.form['value_to_overwrite'], 16),
                             pre_length=chunk_to_overflow_into-data_that_overflows,
                             post_length=end_point_data_after_C-data_that_overflows,
                             pre_presets=json.loads(request.form['pre_presets']),
                             post_presets=json.loads(request.form['post_presets'])
                             )
    arch_bits = {"32": 0xffffffff, "64": 0xffffffffffffffff}
    mask = arch_bits[request.form['bits']]
    pre, metadata, post = hpc.generate_payload()
    payload = payload %(repr(pre), repr(post), hex(metadata[0] & mask), hex(metadata[1] & mask))
    print payload
    return payload



def generate_table(name, tableoutput="DUMP.html"):
    import itertools
    dump = open("stack_dump.txt", "r").readlines()
    dump = [i.strip() for i in dump]
    dump = [i.split() for i in dump]

    start_addr = int(dump[0][0][:-1], 16)

    dump = [i[1:] for i in dump]
    dump = list(itertools.chain(*dump))

    row_count = len(dump) / 4
    if len(dump) % 4 != 0:
        row_count += 1
    column_count = 4

    dump_i = 0

    html  = '<table border="3">\n'
    for i in xrange(row_count):
        html += '<tr>\n'
        for j in xrange(column_count):
            html += '<td>'
            if dump_i < len(dump):
                val = hex(start_addr) + ":" + dump[dump_i]
                html += '<input type="radio" name="%s" value="%s">%s' %(name, val, val)
                dump_i += 1
                start_addr += 4
            else:
                html += ''
            html += '</td>\n'
        html += '</tr>\n'
    html += '</table>\n'

    open(tableoutput, "w").write(html)
    return html

def extract_stack_dump(request):
    dump = request.files['stack_dump']
    dump.save('stack_dump.txt')

if __name__ == '__main__':
    app.debug = True
    app.run()
