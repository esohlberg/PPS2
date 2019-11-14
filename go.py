import pps2 as p
if __name__ == "__main__":
    p.problem5('esohlberg')
'''
    zerobyte = '\x00'
    querystring = ''
    for i in range(0, 30):
        querystring += zerobyte
    originalquerystring = querystring

    listofdicts = []
    for i in range(0, 20):
        listofdicts.append({})
    for z in range(0, 500):
        querystring = originalquerystring
        for i in range(0, 20):
            bytesstring = p.make_query_quiet('one', 'esohlberg', querystring)
            #print(len(bytesstring))
            querystring = querystring[0:-1]
            bytesaray = list(bytesstring)
            if bytesstring[30] in listofdicts[i]:
                listofdicts[i][bytesstring[30]] += 1
            else:
                listofdicts[i][bytesstring[30]] = 1

    answerbytes = []
    for i in range(0, 20):
        maxnum = 0
        maxbyte = None
        for key, value in listofdicts[i].items():
            if value > maxnum:
                maxnum = value
                maxbyte = key
        answerbytes.append(maxbyte)
    c = bytes(answerbytes)
    print(len(c))
    print(str(c, errors = 'replace'))
'''