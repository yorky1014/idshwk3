global vecip : vector of addr={127.0.0.1};



global vecagent1 : vector of string={};



global vecagent2 : vector of string={};



global vecagent3 : vector of string={};



global vecagentnum : vector of int={};



#global numofpack = 0;



event zeek_init()



    {



        #print "zeek init";



    }







event http_header(c: connection, is_orig: bool, name: string, value1: string)



    {



        if( name == "USER-AGENT" )# if header's name = User-Agent



            {



                local value = to_lower(value1);



            	#print "userAgent comes";



            	#++numofpack;



                local find = -1;



                for ( ip in vecip )



                    {



                        if ( vecip[ip] == c$id$orig_h)#find same ip in vecip



                            {



                            	#print "find";



                            	find = -1 ;



                                if ( vecagentnum[ip] == 1 )



                                    {



                                        if ( vecagent1[ip] != value )



                                            {



                                                vecagent2[ip] = value;



                                                vecagentnum[ip] = 2;



                                                find = -1;



                                                break;



                                            }



                                        break;



                                    }



                                if ( vecagentnum[ip] == 2 )



                                    {



                                        if (( vecagent1[ip] != value )&&( vecagent2[ip] != value))



                                            {



                                                vecagent3[ip] = value;



                                                vecagentnum[ip] = 3;



                                                find = -1;



                                                break;



                                            }



                                            break;



                                    }



                                if ( vecagentnum[ip] == 3 )



                                    {



                                    	find = -1;



                                        break;#do nothing



                                    }



                            }



                        else#do not find the same one



                            {



                            	#print "do not find";



                                find = 0;#means it is a new origin ip



                            }



                    } 



                if ( find == 0 )



                    {



                    	#print "add to vecip";



                        vecip[|vecip|] = c$id$orig_h;#set the new ip and it's user-agent's name;



                        vecagent1[|vecip|-1] = value;



                        vecagentnum[|vecip|-1] = 1;



                    }



            }



        else



            {



                #do nothing;



            }



    



    }







event zeek_done()



    {



    	#print "zeek done";



    	#print |vecip|;



    	#print |vecagentnum|;



    	#print numofpack;



        for ( x in vecagentnum)



            {



            	#print vecip[x];



                if ( vecagentnum[x] == 3 )



                    {



                        print fmt("%s is a proxy", vecip[x]);



                    }



            }



    }
