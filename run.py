import pps2 as p
if __name__ == "__main__":
    listofdicts = []
    zxy = 50
    for i in range(0,zxy):
        listofdicts.append({})
    for z in range(0, 300):
        bytesstring = p.make_query('one', 'esohlberg', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        bytesarray = list(bytesstring)
        for i in range(0,zxy):
            if bytesarray[i] in listofdicts[i]:
                listofdicts[i][bytesarray[i]] += 1
            else:
                listofdicts[i][bytesarray[i]] = 1
    
    maxposition = 0
    maxnum = 0
    specialbyte = None    
    for i in range(0, zxy):
        for key, value in listofdicts[i].items():
            if value > maxnum:
                specialbyte = key
                maxposition = i
                maxnum = value
    print('Most occuring was ')
    print(specialbyte)
    print(' at position ')
    print(str(maxposition))
    print(' with ')
    print(str(maxnum))
    print(' occurences.')

