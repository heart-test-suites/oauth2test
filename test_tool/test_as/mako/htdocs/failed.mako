<%!

from otest.check import STATUSCODE

def test_output(out):
    """

    """
    element = ["<h3>Test output</h3>", "<pre><code>"]
    for item in out:
        if isinstance(item, tuple):
            element.append("__%s:%s__" % item)
        else:
            element.append("[%s]" % item["id"])
            element.append("\tstatus: %s" % STATUSCODE[item["status"]])
            try:
                element.append("\tdescription: %s" % (item["name"]))
            except KeyError:
                pass
            try:
                element.append("\tinfo: %s" % (item["message"]))
            except KeyError:
                pass
    element.append("</code></pre>")
    return "\n".join(element)
%>

<%!
from otest.events import layout

def trace_output(events):
    """

    """
    element = ["<h3>Trace output</h3>", "<pre><code>"]
    start = 0
    for event in events:
        if not start:
            start = event.timestamp
        element.append(layout(start, event))
    element.append("</code></pre>")
    return "\n".join(element)
%>

<!DOCTYPE html>


<html>
  <head>
    <title>HEART Oauth2 AS Test</title>
    <link rel="stylesheet" type="text/css" href="${base}/static/theme.css">
  </head>
  <body>
     <h2>Result</h2>
       ${test_output(output)}
       ${trace_output(events)}
  </body>
</html>