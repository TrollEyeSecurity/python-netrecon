import http.client as client
import base64


def get_vsphere_session(hostname, username, password, port=443):
    headers = {'Accept': 'text/plain',
               'Content-type': 'application/json',
               'Host': hostname,
               'Authorization': 'Basic %s' % base64.b64encode('%s:%s' % (username,
                                                                         password))}
    path = '/rest/com/vmware/cis/session'
    conn = client.HTTPSConnection(hostname, port)
    conn.request('POST',
                 path,
                 headers=headers)
    resp = conn.getresponse()
    if resp.status == 200:
        del headers['Authorization']

        headers['Cookie'] = resp.getheader('Set-Cookie')
        return headers
    return
