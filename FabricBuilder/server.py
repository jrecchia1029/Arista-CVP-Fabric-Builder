import cherrypy
import xlrd
import xlwt
import json
import os

localDir = os.path.dirname(__file__)
absDir = os.path.join(os.getcwd(), localDir)


    

def main():
    #DO STUFF HERE
    cherrypy.quickstart(Handler(),'/','handler.conf')



if __name__ == '__main__':
    main()
