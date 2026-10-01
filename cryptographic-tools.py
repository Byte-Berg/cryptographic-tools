from tkinter import *
#import tkinter.tix
import tkinter.ttk
import datetime
import tkinter
import random
import hashlib
import multiprocessing
import sys
from tkinter import filedialog
statik_safe_prime_9000bit = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547
statik_generator = 2
menu_and_button_color = "#6a7ddb"
#menu_and_button_color = "#ffffff"
class block_cypher_parts():

    def checksumm_anhängen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not Bytearray. it is ",type(zu_verarbeitendes_array))
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array)
        checksum = shaobj.digest()
        zu_verarbeitendes_array = zu_verarbeitendes_array + checksum
        return zu_verarbeitendes_array

    def checksumm_prüfen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not Bytearray. it is ",type(zu_verarbeitendes_array))
        erzugte_prüfsumme = bytearray()
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array[0:-32])
        erzugte_prüfsumme = shaobj.digest()


        if zu_verarbeitendes_array[-32:] == erzugte_prüfsumme:
            return True
        else:
            return False

    def festel_struktur_verschlüsseln(self, liste_pw_aray, aray_input_block):

        """
        #hier kommt eine feistel struktur hin. am anfang zum testen ist die f funktion ein xor. wen diese funktionirt dann kann sie durch eine hash funktion ersetzt werden
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))

        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8]:
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
        #return beispiel_block_array
        """

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_encyption(aray_input_block, liste_pw_aray)

    def festel_struktur_entschlüsseln(self, liste_pw_aray, aray_input_block):

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray)
        #aray_input_block = blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray[8:])

        """
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))
        #assert type(aray_input_block) == bytearray
        if type(aray_input_block) != bytearray:
            raise Exception("type aray_input_block is not bytearray, it is: ",type(aray_input_block))
        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8:-1]:
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()

        return beispiel_block_array
        """

    def pw_list_gen(self,pw_text_string):
        hashobj_for_konst = hashlib.sha3_512()
        """ranobj = random.SystemRandom()"""
        start_array = bytearray(pw_text_string, "UTF-8")
        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        konstant_start = bytearray("start","UTF-8")


        list_of_konstanst = []
        hashobj = hashlib.sha3_512()
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj_for_konst.update(konstant_start)
                konstant_start = hashobj_for_konst.digest()
                hashobj_for_konst = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            list_of_konstanst.append(konstant_start)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""

        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj.update(start_array + list_of_konstanst[rundencounter])
                start_array = hashobj.digest()
                hashobj = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            pw_list.append(start_array)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""
        self.pw_array_liste = pw_list

        #return pw_list

    def xor(self,a, b):
        if len(a) != len(b):
            raise Exception("array lengh for xor is uneven ",len(a)," ",len(b))
        #assert len(a) == len(b)
        output_array = []
        index_counter = 0
        integer_a = int.from_bytes(a,"big")
        integer_b = int.from_bytes(b,"big")

        xoredint = integer_a ^ integer_b
        return bytearray(int.to_bytes(xoredint,len(a),"big"))
        """
        for i in a:
            output_array.append(a[index_counter] ^ b[index_counter])
            index_counter += 1

        output_array = bytearray(output_array)
        return output_array
        """



    def get_rand_bytearray(self,length_in_bits):
        #assert length_in_bits % 8 == 0
        if length_in_bits % 8 != 0:
            raise Exception("can not get a random array with lenght ",length_in_bits)
        randobj = random.SystemRandom()
        randarray = bytearray()
        randarray = randarray + randobj.getrandbits(length_in_bits).to_bytes((length_in_bits // 8), "big")
        return randarray

    def modular_addition_of_two_arrays_with_len_32(self,array_01,array_02):
        if len(array_01) != 32 or len(array_02) != 32:
            raise Exception("input lengh error")
        if type(array_01) != bytearray or type(array_02) != bytearray:
            raise Exception("input type error")


        #modulo_size = pow(2, 256)
        modulo_size = 115792089237316195423570985008687907853269984665640564039457584007913129639936
        array_03 = bytearray()
        array_01_int = int.from_bytes(array_01, "big")
        array_02_int = int.from_bytes(array_02, "big")
        array_03_int = (array_01_int + array_02_int) % modulo_size
        array_03 = int.to_bytes((array_03_int), 32, "big")

        return bytearray(array_03)

    def reverse_modular_addition_of_two_arrays_with_len_32(self,array_01,array_02):
        if len(array_01) != 32 or len(array_02) != 32:
            raise Exception("input lengh error")
        if type(array_01) != bytearray or type(array_02) != bytearray:
            raise Exception("input type error")

        #modulo_size = pow(2, 256)
        modulo_size = 115792089237316195423570985008687907853269984665640564039457584007913129639936
        array_03 = bytearray()
        array_01_int = int.from_bytes(array_01, "big")
        array_02_int = int.from_bytes(array_02, "big")

        # weil ist x + y wahr kleiner als mod bei der addition
        array_03_int = (array_01_int - array_02_int)
        if array_03_int >= 0:
            array_03 = int.to_bytes((array_03_int % modulo_size ), 32, "big")
            #print("is bigger")


        elif array_03_int == 0:
            array_03 = int.to_bytes(array_03_int,32,"big")

        else:
            array_03_int = modulo_size + (array_01_int - array_02_int)
            array_03 = int.to_bytes((array_03_int % modulo_size ) , 32, "big")
            #print("zweig 2")
        return bytearray(array_03)

    def test_for_mod_addition(self):
        array_01 = bytearray("test", "UTF-8")
        array_02 = bytearray("00000000TEST2", "UTF-8")

        #test_array_big = int.to_bytes((pow(2, 256) - 1 ), 32, "big")
        test_array_big = int.to_bytes(0,32,"big")
        print("test array big : ",test_array_big)
        while len(array_01) != 32:
            array_01 = bytearray("0", "UTF-8") + array_01
        while len(array_02) != 32:
            array_02 = array_02 + bytearray("0", "UTF-8")
        blockobj = block_cypher_parts()
        array_test = blockobj.modular_addition_of_two_arrays_with_len_32(array_01, array_02)
        print("after addition ",array_test)
        array_test = blockobj.reverse_modular_addition_of_two_arrays_with_len_32(array_test, array_02)
        print("after reverse ",array_test)
        print("")
        array_test = blockobj.modular_addition_of_two_arrays_with_len_32(array_01, bytearray(test_array_big))
        print("after addition ", array_test)
        array_test = blockobj.reverse_modular_addition_of_two_arrays_with_len_32(array_test, bytearray(test_array_big))
        print("after reverse ",array_test)

    def bytearray_shift_right(self,array_01,shiftnummber):
        if type(shiftnummber) != int or type(array_01) != bytearray:
            raise Exception("input type error")
        array_shifted = bytearray()
        array_shifted = array_01[(shiftnummber):] + array_01[0:(shiftnummber)]

        return array_shifted

    def bytearray_shift_left(self,array_01,shiftnummber):
        if type(shiftnummber) != int or type(array_01) != bytearray:
            raise Exception("input type error")

        array_shifted = bytearray()
        array_shifted = array_01[-shiftnummber:] + array_01[0:-shiftnummber]

        return array_shifted

    def ARX_cypher_one_round_encyption(self,array_01,roundkey_array_in_list):
        if len(array_01) != 64:
            raise Exception("len array is not 64")
        #roundkey size musst be 256
        #for i in roundkey_array_in_list:
        #    if len(i) != 64:
        #        raise Exception("falsche round key leght. die funktion geht von nem 65 byte sha3 input aus")
            #den schrit vileicht ibn der nachsten zeile auslase und unten zwei mal abschnitt mit i[0:32] und i[32:]
        array_links = array_01[0:32]
        array_rechts = array_01[32:]
        neue_liste_roundkeys = []
        """
        for i in roundkey_array_in_list:
            neue_liste_roundkeys.append(i[0:32])
            neue_liste_roundkeys.append(i[32:])
        roundkey_array_in_list = neue_liste_roundkeys"""


        for i in roundkey_array_in_list:
            array_links = self.bytearray_shift_right(array_links, 7)
            array_links = self.modular_addition_of_two_arrays_with_len_32(array_links, array_rechts)
            array_links = self.xor(array_links, i[0:32])
            array_rechts = self.bytearray_shift_left(array_rechts, 3)
            array_rechts = self.xor(array_rechts, array_links)

            array_links = self.bytearray_shift_right(array_links, 7)
            array_links = self.modular_addition_of_two_arrays_with_len_32(array_links, array_rechts)
            array_links = self.xor(array_links, i[32:])
            array_rechts = self.bytearray_shift_left(array_rechts, 3)
            array_rechts = self.xor(array_rechts, array_links)

        return bytearray(array_links) + bytearray(array_rechts)

    def ARX_cypher_one_round_decyption(self,array_01,roundkey_array_in_list):
        if len(array_01) != 64:
            raise Exception("len array is not 64")
        for i in roundkey_array_in_list:
            if len(i) != 64:
                raise Exception("falsche round key leght. die funktion geht von nem 65 byte sha3 input aus")
        # roundkey size musst be 256
        array_links = array_01[0:32]
        array_rechts = array_01[32:]
        neue_liste_roundkeys = []
        #for i in roundkey_array_in_list:
        #    neue_liste_roundkeys.append(i[0:32])
        #    neue_liste_roundkeys.append(i[32:])
        #roundkey_array_in_list = neue_liste_roundkeys

        for i in roundkey_array_in_list[::-1]:
            array_rechts = self.xor(array_rechts,array_links)
            array_rechts = self.bytearray_shift_right(array_rechts,3)
            array_links = self.xor(array_links,i[32:])
            array_links = self.reverse_modular_addition_of_two_arrays_with_len_32(array_links,array_rechts)
            array_links = self.bytearray_shift_left(array_links,7)

            array_rechts = self.xor(array_rechts, array_links)
            array_rechts = self.bytearray_shift_right(array_rechts, 3)
            array_links = self.xor(array_links, i[0:32])
            array_links = self.reverse_modular_addition_of_two_arrays_with_len_32(array_links, array_rechts)
            array_links = self.bytearray_shift_left(array_links, 7)

        return bytearray(array_links) + bytearray(array_rechts)

class SafePrimeGenerator:

    """Benötigt "import random"""
    """die schleife hier ist um mindestens den faktor 2 mal langsamer als die schleife aus dh exchange??wie kommt das
    liegt das an den funktionsaufrufen der class"""
    """wurde etwas verbesser da die anzahlk der rabbin miller test mit zufälliger base auf 400 gestellt wahr und damit die zeit
    pro echter primzahl 8 mal so hoch wahr wie in der DH funktion hinzterlegt. Es sind jedoch noch geschwindickeits unterschiede zu sehen
    ob die an der verwendung von "class" liegt oder an der unterschiedlichen schleife beidder datein muss sich nochj zeigen"""

    def fermat_prime_test(self,number):
        if number < 4 or number % 2 == 0:
            return False

        for i in range(2, 14, 1):
            fermet = pow(i, (number - 1), number)
            if fermet != 1 and fermet != (number - 1):
                return False
        return True


    def prime_gen(self,bitlenght_prime):
        rand = random
        testprime = self.millerrabinprimetest
        Prime = 0
        ist_Prime = False
        while ist_Prime == False:
            Prime = rand.getrandbits(bitlenght_prime)
            if Prime % 2 == 1:
                if Prime % 3 != 0:
                    if Prime % 5 != 0:
                        if Prime % 7 != 0:
                            if Prime % 11 != 0:
                                if Prime % 13 != 0:
                                    if Prime % 17 != 0:
                                        if Prime % 19 != 0:
                                            Primehalbe = ((Prime - 1) // 2)
                                            if Primehalbe % 2 == 1:
                                                if Primehalbe % 3 != 0:
                                                    if Primehalbe % 5 != 0:
                                                        if Primehalbe % 7 != 0:
                                                            if Primehalbe % 11 != 0:
                                                                if Primehalbe % 13 != 0:
                                                                    if Primehalbe % 17 != 0:
                                                                        if Primehalbe % 19 != 0:
                                                                            if testprime(Prime) == True:
                                                                                if testprime(Primehalbe) == True:
                                                                                    ist_Prime = True
        return Prime


    def expo_big(self, base, Expo, Mod):
        """
        int_liste = []
        ergebniss = 1
        while Expo != 0:
            if Expo % 2 == 1:
                int_liste.append(base)
            Expo = Expo // 2
            base = base ** 2
            base = base % Mod
        for i in int_liste:
            ergebniss = ergebniss * i
            ergebniss = ergebniss % Mod

        return ergebniss
        """
        return pow(base,Expo,Mod)



    def millerrabinprimetest(self,prime):
        """ teste ib input gerade ist oder unter 4 ist"""
        if prime < 4 or prime % 2 == 0:
            return False

        """forme Primzahl zu n -1 = d * (2**j)"""
        ist_float = False
        rando = random.SystemRandom()
        d = 0
        j = 0
        base = 2
        expo = 1
        m = prime - 1
        while ist_float == False:
            """ersetzte vileicht durch if m// (base ** expo) umkehren zu m  * (base ** expo. denn wenn es wieder m ergibt ist nicht gerundet worden"""
            if (m // (pow(base,expo)) * (pow(base,expo))) == m:
                d = m // (pow(base,expo))
                j = expo
                expo += 1
            else:
                ist_float = True
        rundenzahl = 0
        while rundenzahl != 35:
            a = random.SystemRandom.randint(rando, 3, (prime - 2))
            if self.expo_big(a, d, prime) == 1 or self.expo_big(a, d, prime) == prime - 1:
                rundenzahl += 1
            else:
                einmal_true = True
                """ j is not allowed to be 0"""
                if j > 1:
                    for i in range(1, j, 1):
                        """diese schleife verursacht immer fehler beim raussuchen. muss überarbeitet werden"""
                        if self.expo_big(a, (d * (pow(2,i))), prime) == prime - 1 and einmal_true == True:
                            rundenzahl += 1
                            einmal_true = False
                    if einmal_true != False:
                        return False

                elif j == 1 or j == 0:
                    if self.expo_big(a, (d * (2 ** 1)), prime) != prime - 1:
                        return False
                    else:
                        rundenzahl += 1
        return True


class licence_file_check:

    """benotigt import hashlib,rand,datetime,tkinter"""

    def expo_big(self, base, Expo, Mod):
        """
        int_liste = []
        ergebniss = 1
        while Expo != 0:
            if Expo % 2 == 1:
                int_liste.append(base)
            Expo = Expo // 2
            base = base ** 2
            base = base % Mod
        for i in int_liste:
            ergebniss = ergebniss * i
            ergebniss = ergebniss % Mod

        return ergebniss
        """
        return pow(base, Expo, Mod)

    def millerrabinprimetest(self,prime):
        #assert type(prime) == int
        if type(prime) != int:
            raise Exception("type prime is not int. It is ",type(prime))
        """ teste ib input gerade ist oder unter 4 ist"""
        if prime < 4 or prime % 2 == 0:
            return False

        """forme Primzahl zu n -1 = d * (2**j)"""
        ist_float = False
        rando = random.SystemRandom()
        d = 0
        j = 0
        base = 2
        expo = 1
        m = prime - 1
        while ist_float == False:
            """ersetzte vileicht durch if m// (base ** expo) umkehren zu m  * (base ** expo. denn wenn es wieder m ergibt ist nicht gerundet worden"""
            if (m // (base ** expo)) * (base ** expo) == m:
                d = m // (base ** expo)
                j = expo
                expo += 1
            else:
                ist_float = True
        rundenzahl = 0
        while rundenzahl != 12:
            a = random.SystemRandom.randint(rando, 3, (prime - 2))
            if self.expo_big(a, d, prime) == 1 or self.expo_big(a, d, prime) == prime - 1:
                rundenzahl += 1
            else:
                einmal_true = True
                """ j is not allowed to be 0"""
                if j > 1:
                    for i in range(1, j, 1):
                        """diese schleife verursacht immer fehler beim raussuchen. muss überarbeitet werden"""
                        if self.expo_big(a, (d * (2 ** i)), prime) == prime - 1 and einmal_true == True:
                            rundenzahl += 1
                            einmal_true = False
                    if einmal_true != False:
                        return False

                elif j == 1 or j == 0:
                    if self.expo_big(a, (d * (2 ** 1)), prime) != prime - 1:
                        return False
                    else:
                        rundenzahl += 1
        return True

    def Textsig(self, Text, privatekey, Prime,generator):
        #assert type(Text) == str
        if type(Text) != str:
            raise Exception("type Text is not str. It is ",type(Text))
        #assert type(privatekey) == int
        if type(privatekey) != int:
            raise Exception("type privatekey is not int. It is ",type(privatekey))
        #assert type(Prime) == int
        if type(Prime) != int:
            raise Exception("type Prime is not int. It is ",type(Prime))
        #assert type(generator) == int
        if type(generator) != int:
            raise Exception("type generator is not int. It is ",type(generator))
        rand = random
        rand_var = random.SystemRandom.randint(rand, 1, Prime)
        Teilsig_1 = self.expo_big(generator, rand_var, Prime)
        """Randvar darf nie!!! 2 mal verwendet werden da sonst die sicherheit trivial  gebrochen wird"""
        hashvar = hashlib.sha512()
        hashvar.update(bytearray(str(Teilsig_1), "UTF-8"))

        hashvar.update(bytearray(Text, "Utf-8"))
        """nun das ergebnis von hashvar digest in eine int umwandeln. nutze int.from_byte"""
        hashoutput = hashvar.digest()
        hashoutput = int.from_bytes(hashoutput, "big")
        Teilsig_2 = ((hashoutput * privatekey) + rand_var) % ((Prime - 1) // 2)

        """ersetze bald wenn möglich print mit return von zb einer liste"""

        #print("Generator:", generator, "\nPrime:", Prime, "\nHash:Sha512")
        #print("Nachricht:")
        #print(Text)
        #print("Teilsignatur 1:\n", Teilsig_1, "\nTeilsignatur 2:\n", Teilsig_2)
        liste_ergebnnis = []
        liste_ergebnnis.append(Teilsig_1)
        liste_ergebnnis.append(Teilsig_2)
        return  liste_ergebnnis

    def Signaturvery(self, Text, Teilsig1, Teilsig2, Publickey, Prime,Generator):
        #assert type(Text) == str
        if type(Text) != str:
            raise Exception("type Text is not str. It is ",type(Text))
        #assert type(Teilsig1) == int
        if type(Teilsig1) != int:
            raise Exception("type Teilsig1 is not int. It is ",type(Teilsig1))
        #assert type(Teilsig2) == int
        if type(Teilsig2) != int:
            raise Exception("type Teilsig2 is not int. It is ",type(Teilsig2))
        #assert type(Publickey) == int
        if type(Publickey) != int:
            raise Exception("type Publickey is not int.. It is ",type(Publickey))
        #assert type(Prime) == int
        if type(Prime) != int:
            raise Exception("type Prime is not int. it is ",type(Prime))

        "Prüfen der signatur"
        #print("Es steht nur Sha512 zur verfügung")
        generator = Generator
        #print("2 ist der standart genarator")
        ist_Prime = False
        """while ist_Prime == False:

            if self.millerrabinprimetest(Prime) == True:
                if self.millerrabinprimetest(((Prime - 1) // 2)) == True:
                    ist_Prime = True
                else:
                    #print("Warnung die angegebene Zahl ist keine Safe-Prime")
                    #input("belibige taste drücken:")
                    ist_Prime = True

            else:
                print("eingegebene Zahl wahr keine sichere Primzahl")"""

        """wenn richtwert 1 == Richtwert 2 dan ist die signatur richtig"""
        Richtwert_1 = self.expo_big(generator, Teilsig2, Prime)
        """nun expo berechnung für richtwert 2"""
        hashvar = hashlib.sha512()
        hashvar.update(bytearray(str(Teilsig1), "UTF-8"))
        hashvar.update(bytearray(Text, "Utf-8"))
        """nun das ergebnis von hashvar digest in eine int umwandeln. nutze int.from_byte"""
        hashoutput = hashvar.digest()
        hashoutput = int.from_bytes(hashoutput, "big")

        Richtwert_2 = (pow(Publickey, hashoutput, Prime) * Teilsig1) % Prime

        #print(Richtwert_1, "\n", Richtwert_2)
        if Richtwert_1 == Richtwert_2:
            #print("Signatur ist korrekt")
            string = "Signature ist korrekt"
            return string
        else:
            #print("Signatur ist Falsch")
            string = "Signature ist Falsch"
            return string

    def schorr_key_erstellen(self,safe_prime,generator):

        # assert type(safe_prime) == int
        if type(safe_prime) != int:
            raise Exception("type safe_prime is not int. It is ", type(safe_prime))
        # assert type(generator) == int
        if type(generator) != int:
            raise Exception("type generator is not int. it is ", type(generator))
        if generator < 2:
            raise Exception("Generator can not be smaller than 2")
        # assert self.millerrabinprimetest(safe_prime) == True:
        if self.millerrabinprimetest(safe_prime) != True:
            raise Exception("safe_prime is not a safe prime")
        # assert self.millerrabinprimetest(((safe_prime - 1) // 2)) == True
        if self.millerrabinprimetest(((safe_prime - 1) // 2)) != True:
            raise Exception("safe_prime is not a safe prime")

        rand = random.SystemRandom()
        primeminusone = safe_prime - 1
        private_key = rand.randint(1, primeminusone)
        public_key = self.expo_big(generator, private_key, safe_prime)
        liste_ergbenis = []
        liste_ergbenis.append(private_key)
        liste_ergbenis.append(public_key)
        return liste_ergbenis

    def licence_file_check(self):

        safe_prime_for_sig = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547
        gen_for_sig = 2
        pub_key = 49791339798787181475943980757522691254093638842628617239295523900388651186629744856280707731394721043172616869802282548624313237688452899008730981389888573824219961532534906503530052570101086088306064378953743885953707778031615968286296486117176657943893726685188601886146874555254581278189209015775350794129983880042877488942146144961986483460186112053690069063201631403047007642316853649720255527558832750142760329525006888544442592996396973439997586624499725716447616786463426237720456964148204252953606852078332875544779352747521225696037878885208510851339525794588081795698716759787832172402578032625079653665861295466850388539847006724027905937359273929311030640935396578459843712635228581547266909563754658732380870895495246950293882147829291322583428348105934092219272930651805882735982738762713352171741710303423246161549881347663177536054575865588595257628370018262226697641588250953200446038002283053731591383705078998021783772446195401405884554749399638160532175996367090481642157405830287008159442846748154106261056833253073927673881502860189191019521089321274991848453651516289189584869087905134892166424373147013459175440403633949800544090262963011205789712706102881444269734695619502703912465423393409897614388203177872895043989815176776455430799347362118755903045206550602732841714389117929071358619419042489815376016156701725384072980907102796442522406567693840485292263083000237338101050353869950092144300022551461363917600835674554545445979181143076794645884078707671072604533362912426698565654563669777717739801484080898796465765105752046514827801715110598923393790889717242309756884244870810535552280236999942056539698276215758330873798253951341025378375514523159842443123324479205242035257657232548504319707293584157531707119749300760702365196401462334762907994532422850019087863563342482594998374936303350735308991787572603020088459597153179832019034713151232019826755033410399352947218312890098130277266524870504994223334061504965422396205028319646817678244721400458847366378769958690658902787636399506752445197561913158346552695276092390837637511815945877322618447741492675293956905585431580265354927128477304665629159575793794684202148871057162588265810460508655261170391203720654740168537669016873753733948714410468071550936238717576995962273019895526509969660097402346886301219517620368744675451824971845931755844725501340411945710631830400990563738130874696361258512975305067736482031081320121498739977235660700144006693647547531728794169537623680934700035327964445257081652863091162227428763030133911065463663756677191216724926568254121565544678614218949277727914455875651070703686674807538349464483586043752884688071293165997828250536483771932020201237755780563645019431699983

        try:
            fileobj = open("licence.txt","r")
        except:
            error_window = tkinter.Tk()
            error_window.title("Error")
            error_window.anchor("center")
            error_window.wm_minsize(240, 120)
            label_01 = tkinter.Label(error_window, text="Licence File Not found\nPlease check that it is in the same place as the executable")
            label_01.grid(row=0, column=0)
            error_window.mainloop()
            return False
        text_zeile_1 = fileobj.readline()
        text_zeile_2 = fileobj.readline()
        #enfterne die zeilen umbrüche
        text_zeile_1 = text_zeile_1[0:-1]
        text_zeile_2 = text_zeile_2[0:-1]
        #entferne die Zeichen vor und einschlislich mit dem :
        #damit das nur ein reiner zeitdelta string zum ableich wird
        licence_start_datum_delta_string = text_zeile_1.split(":")[1]
        licence_ende_datum_delta_string = text_zeile_2.split(":")[1]

        #print(licence_ende_datum_delta_string)
        #print(licence_ende_datum_delta_string)
        fileobj.close()
        counter = "1"
        liste_fur_sigcheck = []
        fileobj = open("licence.txt", "r")
        while len(counter) != 0:
            counter = fileobj.readline()
            liste_fur_sigcheck.append(counter)
        #print(liste_fur_sigcheck)
        if liste_fur_sigcheck[-1] == "\n" or liste_fur_sigcheck[-1] == "":
            #entfernt aus versehen zugefügten umbruch
            del liste_fur_sigcheck[-1]
        #print(liste_fur_sigcheck)
        #if liste_fur_sigcheck[-2][-1] == "\n":
        #    liste_fur_sigcheck[-2][0:-1]
        #if liste_fur_sigcheck[-1][-1] == "\n":
        #    liste_fur_sigcheck[-1][0:-1]

        fileobj.close()
        fileobj = open("licence.txt", "r")
        string_leght = "h"
        text = ""
        for i in liste_fur_sigcheck[0:-2]:
            text = text + i

        teilsig_1_string = liste_fur_sigcheck[-2]
        teilsig_2_string  = liste_fur_sigcheck[-1]
        #print("signaturtext ",text)
        #achte darauf ob beim signieren mit oder ohne zeilen umbruch gearbeitet wurde
        #in dieser form muss dem text ein zeilenumbruch beim signieren der lizenz hinzugefügt werden

        result = self.Signaturvery(text,int(liste_fur_sigcheck[-2]),int(liste_fur_sigcheck[-1]),pub_key,safe_prime_for_sig,gen_for_sig)
        if datetime.date.fromisoformat(licence_start_datum_delta_string) <= datetime.date.today() and datetime.date.fromisoformat(licence_ende_datum_delta_string) >= datetime.date.today():
            """print("ist im licence bereich")
            print(datetime.date.fromisoformat(licence_start_datum_delta_string))
            print(datetime.date.today())"""
            return True
        else:
            #print("Licence expired")
            error_window = tkinter.Tk()
            error_window.title("Error")
            error_window.anchor("center")
            error_window.wm_minsize(240,120)
            label_01 = tkinter.Label(error_window,text="Licenc Expired")
            label_01.grid(row=0,column=0)
            error_window.mainloop()
            return False

        #print("text test ergebnis=: ",result)

    def Licence_generator(self,private_key,time_delta_licence_start_str,time_delta_licence_end_str,text):
        static_generator = 2
        static_safe_prime = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547


        """Licence start:2022-01-01
           Licence end:2022-01-02
           format year:month:day"""

        if type(time_delta_licence_start_str) != str or type(time_delta_licence_end_str) != str:
            raise Exception("Time delta must both be a str. time_delta_licence_start is ",type(time_delta_licence_start_str)," and time_delta_licence_end is ",type(time_delta_licence_end_str))
        if type(private_key) != int:
            raise Exception("type privatekey must be int. It is ",type(private_key))
        if type(text) != str:
            raise Exception("type Text must be str. It is ",type(text))
        try:
            datetime.date.fromisoformat(time_delta_licence_end_str)
            datetime.date.fromisoformat(time_delta_licence_start_str)
        except:
            raise Exception("time delta str could not be convertet to delta type. Check if formatting i right.\n",time_delta_licence_start_str,"\n",time_delta_licence_end_str)

        text_to_sign = "Licence start:" + time_delta_licence_start_str + "\n" + "Licence end:" + time_delta_licence_end_str + "\n" + text + "\n"

        sigobj = licence_file_check()
        list_signaturen = sigobj.Textsig(text_to_sign,private_key,static_safe_prime,static_generator)

        text_for_file = text_to_sign + str(list_signaturen[0]) + "\n" + str(list_signaturen[1])
        fileobj = open("licence.txt", "w")
        fileobj.write(text_for_file)
        fileobj.close()

class Hash_based_blockcypher_mit_cbc():
    """benötigt import random,hashlib"""

    counter_array = bytearray()
    """nutze möglichst bald eine andere xor function die nach jemen stück ein byte aus demm array löscht. dann packe noch eine if schleife in die counter finction die auslöst das counter incement 1 wenn len counter array = 0 ist"""
    pw_array_liste = []

    def xor(self,a, b):
        if len(a) != len(b):
            raise Exception("array lengh for xor is uneven ",len(a)," ",len(b))
        #assert len(a) == len(b)
        output_array = []
        index_counter = 0
        integer_a = int.from_bytes(a,"big")
        integer_b = int.from_bytes(b,"big")

        xoredint = integer_a ^ integer_b
        return bytearray(int.to_bytes(xoredint,len(a),"big"))
        """
        for i in a:
            output_array.append(a[index_counter] ^ b[index_counter])
            index_counter += 1

        output_array = bytearray(output_array)
        return output_array
        """

    def pw_list_gen(self, pw_text_string):
        hashobj_for_konst = hashlib.sha3_512()
        """ranobj = random.SystemRandom()"""
        start_array = bytearray(pw_text_string, "UTF-8")
        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        konstant_start = bytearray("start", "UTF-8")

        list_of_konstanst = []
        hashobj = hashlib.sha3_512()
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj_for_konst.update(konstant_start)
                konstant_start = hashobj_for_konst.digest()
                hashobj_for_konst = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            list_of_konstanst.append(konstant_start)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""

        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj.update(start_array + list_of_konstanst[rundencounter])
                start_array = hashobj.digest()
                hashobj = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            pw_list.append(start_array)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""
        self.pw_array_liste = pw_list

        return pw_list


    def get_rand_bytearray(self,length_in_bits):
        #assert length_in_bits % 8 == 0
        if length_in_bits % 8 != 0:
            raise Exception("can not get a random array with lenght ",length_in_bits)
        randobj = random.SystemRandom()
        randarray = bytearray()
        randarray = randarray + randobj.getrandbits(length_in_bits).to_bytes((length_in_bits // 8), "big")
        return randarray

    def text_input(self,):
        text_string = ""
        schleifen_var = False
        print("Bitte Text eingeben.Enter für Zeilen umbruch. Wenn Fertig Exit eingeben")
        while schleifen_var == False:
            teil_string = input()
            if teil_string == "Exit":
                schleifen_var = True
            else:
                text_string = text_string + teil_string + "\n"
        return text_string

    def festel_struktur_verschlüsseln(self, liste_pw_aray, aray_input_block):

        """
        #hier kommt eine feistel struktur hin. am anfang zum testen ist die f funktion ein xor. wen diese funktionirt dann kann sie durch eine hash funktion ersetzt werden
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))

        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8]:
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
        #return beispiel_block_array
        """

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_encyption(aray_input_block, liste_pw_aray)

    def festel_struktur_entschlüsseln(self, liste_pw_aray, aray_input_block):

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray)
        #aray_input_block = blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray[8:])

        """
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))
        #assert type(aray_input_block) == bytearray
        if type(aray_input_block) != bytearray:
            raise Exception("type aray_input_block is not bytearray, it is: ",type(aray_input_block))
        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8:-1]:
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()

        return beispiel_block_array
        """


    def get_new_rand_counter(self):
        randobj = random
        new_counter_array = 0
        new_counter_array = randobj.randint(0,(2**512))
        new_counter_array = new_counter_array.to_bytes(64,"big")
        self.counter_array = bytearray(new_counter_array)

    def counter_array_increment(self):
        neuer_counterstand = int.from_bytes(self.counter_array, "big")
        neuer_counterstand = (neuer_counterstand + 1) % pow(2, 512)
        self.counter_array = neuer_counterstand.to_bytes(64, "big", )

    def counter_mode_mit_rand_counter(self,zu_verarbeitendes_array):
        """ist nur für einzelnen aufruf geeignet weil ansonsten die self.get rand counter als classenvar ausgelagert werden müsste"""
        zum_xor_zu_verwendeten_array = bytearray()
        self.get_new_rand_counter()
        rand_counter_und_output_array = bytearray(self.counter_array)
        """in zeile 118 darf das bytearray nicht entfernt werden weil sonst aus irgendeinem grund der counter wert nach incermentirung unten weiter gegeben wird"""
        #print("counter beim verschlüsseln ",self.counter_array)

        while len(zum_xor_zu_verwendeten_array) <= len(zu_verarbeitendes_array):
            block = self.festel_struktur_verschlüsseln(self.pw_array_liste,self.counter_array)
            zum_xor_zu_verwendeten_array = zum_xor_zu_verwendeten_array + block
            self.counter_array_increment()
        #print("xor element verschlüsseln ",zum_xor_zu_verwendeten_array)
        #print("pwliste verschlüsseln ",self.pw_array_liste)
        output = bytearray()
        #print(rand_counter_und_output_array)
        output = self.xor(zu_verarbeitendes_array,zum_xor_zu_verwendeten_array[0:len(zu_verarbeitendes_array)])
        rand_counter_und_output_array = rand_counter_und_output_array + output

        return rand_counter_und_output_array

    def counter_mode_mit_rand_counter_entschlüsseln(self, zu_verarbeitendes_array):
        zum_xor_zu_verwendeten_array = bytearray()
        self.counter_array = zu_verarbeitendes_array[0:64]
        #print(type(self.counter_array))
        zu_verarbeitendes_array = zu_verarbeitendes_array[64:]
        #print(len(zu_verarbeitendes_array))
        #print("counter beim entschlüsseln ", self.counter_array)


        while len(zum_xor_zu_verwendeten_array) <= len(zu_verarbeitendes_array):
            block = self.festel_struktur_verschlüsseln(self.pw_array_liste, self.counter_array)
            zum_xor_zu_verwendeten_array = zum_xor_zu_verwendeten_array + block
            self.counter_array_increment()
        #print("xor array entschlüsseln ",zum_xor_zu_verwendeten_array)
        #print("pwliste entschlüsseln ", self.pw_array_liste)
        output_array = bytearray()
        output_array = self.xor(zu_verarbeitendes_array, zum_xor_zu_verwendeten_array[0:len(zu_verarbeitendes_array)])


        return output_array

    def checksumm_anhängen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not Bytearray. it is ",type(zu_verarbeitendes_array))
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array)
        checksum = shaobj.digest()
        zu_verarbeitendes_array = zu_verarbeitendes_array + checksum
        return zu_verarbeitendes_array


    def checksumm_prüfen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not Bytearray. it is ",type(zu_verarbeitendes_array))
        erzugte_prüfsumme = bytearray()
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array[0:-32])
        erzugte_prüfsumme = shaobj.digest()


        if zu_verarbeitendes_array[-32:] == erzugte_prüfsumme:
            return True
        else:
            return False



    def cbc_mode_cypher_verschlüsseln(self,plaintext_aray,xor_vorheriger_cyphertext_block,braucht_es_padding,pw_array_liste):
        #diese funktion fügt das xor_array_nicht dem return array zu_der erste block muss manuel dem file vor dem funktionsaufruf hinugefügt werden

        #assert type(plaintext_aray) == bytearray
        if type(plaintext_aray) != bytearray:
            raise Exception("type plaintext_array is not bytearray. It is ",type(plaintext_aray))
        #assert type(xor_vorheriger_cyphertext_block) == bytearray
        if type(xor_vorheriger_cyphertext_block) != bytearray:
            raise Exception("type xor_vorherriger_cyphertext_block is not bytearray. It is ",type(xor_vorheriger_cyphertext_block))
        #assert type(braucht_es_padding) == bool
        if type(braucht_es_padding) != bool:
            raise Exception("braucht_es_padding is not type bool. It is type ",type(braucht_es_padding))
        #assert type(pw_array_liste) == list
        if type(pw_array_liste) != list:
            raise Exception("type pw_array_list is not list. It is ",type(pw_array_liste))
        if braucht_es_padding == False:
            # assert len(plaintext_aray) % 64 == 0 fehler datei braucht padding
            if len(plaintext_aray) % 64 != 0:
                raise Exception("can only not be padded if len plaintext array is a multible of blocklengh")

        if braucht_es_padding == True:
            plaintext_aray.append(1)
            plaintext_aray.append(0)

            while len(plaintext_aray) % 64 != 0:
                plaintext_aray.append(0)

        #mache eine schleife mit del[index] fur die verschlüsselungsrotine
        cyphertext_array = bytearray()
        #cyphertext_array = cyphertext_array + xor_vorheriger_cyphertext_block
        vorheriger_cypher_block = xor_vorheriger_cyphertext_block
        local_xor = self.xor
        local_festel_struktur_verschlüsseln = self.festel_struktur_verschlüsseln
        while len(plaintext_aray) != 0:
            #encryption loop
            zu_xorender_plaintext_block = plaintext_aray[:64]
            zu_verschusselnder_plaintext_block_xored = local_xor(zu_xorender_plaintext_block,vorheriger_cypher_block)
            cyphertext_block = local_festel_struktur_verschlüsseln(pw_array_liste,zu_verschusselnder_plaintext_block_xored)
            #print("xor block verschlsseln :",vorheriger_cypher_block)
            vorheriger_cypher_block = cyphertext_block
            #fehler ling irgentwo beim xor
            del plaintext_aray[:64]
            #plaintext_aray = plaintext_aray[64:]
            cyphertext_array += cyphertext_block




        return cyphertext_array


    def cbc_mode_cypher_entschlüsseln(self,cyphertext_array,xor_vorheriger_cyphertext_block,pw_array_liste,padding_zu_entfernen):
        #assert len(cyphertext_array) % 64 == 0
        if len(cyphertext_array) % 64 != 0:
            raise Exception("len cyphertext_array must be multible of 64 bytes. It has a lenght of  ",len(cyphertext_array)," ")
        #assert len(xor_vorheriger_cyphertext_block) % 64 == 0
        if len(xor_vorheriger_cyphertext_block) % 64 != 0:
            raise Exception("len xor_vorheriger_cyphertext_block must be multible of 64 bytes. It has a lenght of  ",len(cyphertext_array)," ",)
        #assert type(cyphertext_array) == bytearray
        if type(cyphertext_array) != bytearray:
            raise Exception("type cyphertext_array is not bytearray. It is ",type(cyphertext_array))
        #assert type(xor_vorheriger_cyphertext_block) == bytearray
        if type(xor_vorheriger_cyphertext_block) != bytearray:
            raise Exception("type xor_vorheriger_cyphertext_block is not bytearray. It is ",type(xor_vorheriger_cyphertext_block))
        #assert type(pw_array_liste) == list
        if type(pw_array_liste) != list:
            raise Exception("type pw_array_liste is not list. It is ",type(pw_array_liste))
        #assert type(padding_zu_entfernen) == bool
        if type(padding_zu_entfernen) != bool:
            raise Exception("type padding_zu_entfernen is not bool. It is ",type(padding_zu_entfernen))
        output_plaintext_aray = bytearray()
        block_counter = 0
        gesammt_array_fur_xor = xor_vorheriger_cyphertext_block + cyphertext_array
        cyphertext_array_1 = cyphertext_array


        vorherriger_block = xor_vorheriger_cyphertext_block
        while len(cyphertext_array_1) != 0:
            cyphertext_block = cyphertext_array_1[:64]
            plaintext_block_xored = self.festel_struktur_entschlüsseln(pw_array_liste,cyphertext_block)
            plaintext_block = self.xor(plaintext_block_xored,gesammt_array_fur_xor[:64])
            output_plaintext_aray = output_plaintext_aray + plaintext_block
            #print("xor block entschlüsseln : ",gesammt_array_fur_xor[:64])
            vorherriger_block = cyphertext_block
            del cyphertext_array_1[:64]
            del gesammt_array_fur_xor[:64]



        if padding_zu_entfernen == True:
            output_plaintext_aray = output_plaintext_aray[::-1]
            index_counter_zum_entfernen = 0
            for i in output_plaintext_aray:
                if i == 0:
                    index_counter_zum_entfernen += 1
                if i == 1:
                    index_counter_zum_entfernen += 1
                    break
            output_plaintext_aray = output_plaintext_aray[::-1]
            output_plaintext_aray = output_plaintext_aray[:-index_counter_zum_entfernen]

        return output_plaintext_aray



    def cbc_mode_menue_funktion_encryption(self,pw_string,filepath_string,filename_output,entry_result):
        entry_result.insert(0,"start")
        root.update()
        #print("danach")

        max_size_in_bytes = "3"
        fileobj_for_loop = open(filepath_string,"rb")
        while len(max_size_in_bytes) != 0:
            max_size_in_bytes = fileobj_for_loop.read(200000)
        max_size_in_bytes = fileobj_for_loop.tell()
        fileobj_for_loop.close()
        print(max_size_in_bytes)

        #assert type(filename_output) == str
        if type(filename_output) != str:
            raise Exception("type filename_output is not str. It is ",type(filename_output))
        #assert type(filepath_string) == str
        if type(filepath_string) != str:
            raise Exception("type filepath_string is not str. It is ",type(filepath_string))
        #assert type(pw_string) == str
        if type(pw_string) != str:
            raise Exception("type pw_string is not str. It is ",type(pw_string))

        pw_list_for_encryption_funktion = self.pw_list_gen(pw_string)
        #print(type(pw_list_for_encryption_funktion)," ",pw_list_for_encryption_funktion)
        #does nt return list. sets class var instead
        fileinput_1 = open(filepath_string,"rb")
        #fileoutput_1 = open((filename_output + ".crypt"),"wb")
        fileoutput_1 = open((filename_output), "wb")
        first_block = self.get_rand_bytearray(64 * 8)


        blocklesegroße = 64 * 16000   #muss ein multible von blockgröße sein und nicht kleiner als 2 mal 64 damit das xor vom vorblock genommmen werden kann

        fileoutput_1.write(first_block)
        local_var_pw_array_list = self.pw_array_liste
        local_function_cbc_mode_cypher_verschlüsseln = self.cbc_mode_cypher_verschlüsseln
        array = bytearray(fileinput_1.read(blocklesegroße))
        while len(array) % 64 == 0 and len(array) != 0 :
            cyphertext_array = local_function_cbc_mode_cypher_verschlüsseln(array,first_block,False,local_var_pw_array_list)
            first_block = cyphertext_array[-64:]
            fileoutput_1.write(cyphertext_array)
            array = bytearray(fileinput_1.read(blocklesegroße))
            string_for_progress = str(fileinput_1.tell()) + " of " + str(max_size_in_bytes) + " bytes encrypted " + str(((100 / max_size_in_bytes) * fileinput_1.tell())//1 ) + "%"
            entry_result.delete(0,END)
            entry_result.insert(0, string_for_progress)
            root.update()
        if len(array) == 0 or len(array) % 64 != 0:
            cyphertext_array = local_function_cbc_mode_cypher_verschlüsseln(array,first_block,True,local_var_pw_array_list)
            fileoutput_1.write(cyphertext_array)
        fileoutput_1.close()
        fileinput_1.close()

    def cbc_mode_menue_funktion_decryption(self, pw_string, filepath_string, filenamestring_after_decyption,enty_result):
        # assert type(pw_string) == str
        if type(pw_string) != str:
            raise Exception("type pw_string is not str. It is ", type(pw_string))
        # assert type(filepath_string) == str
        if type(filepath_string) != str:
            raise Exception("type filepath_string is not str. It is ", type(filepath_string))

        enty_result.insert(0, "start")
        root.update()
        # print("danach")

        max_size_in_bytes = "3"
        fileobj_for_loop = open(filepath_string, "rb")
        while len(max_size_in_bytes) != 0:
            max_size_in_bytes = fileobj_for_loop.read(200000)
        max_size_in_bytes = fileobj_for_loop.tell()
        fileobj_for_loop.close()
        print(max_size_in_bytes)

        pw_list_for_decryption = self.pw_list_gen(pw_string)
        fileinput = open(filepath_string, "rb")

        # fileoutput = open(filepath_string[:-5],"wb")
        fileoutput = open(filenamestring_after_decyption, "wb")
        block_input_size = 64 * 16000
        first_block = bytearray(fileinput.read(64))
        array_liste = []
        for i in range(4):
            array_liste.append(bytearray(fileinput.read(block_input_size)))

        pw_liste_local_var = self.pw_array_liste
        local_cbc_mode_cypher_entschlüsseln = self.cbc_mode_cypher_entschlüsseln
        index = 0
        # print("array_liste vor schleife: ",array_liste)
        while True:
            cyphertext_array = array_liste[0]
            # print("durchgang i:",cyphertext_array)
            if len(cyphertext_array) == block_input_size:
                array_zum_schreiben = local_cbc_mode_cypher_entschlüsseln(bytearray(cyphertext_array), first_block,
                                                                          pw_liste_local_var,
                                                                          False)  # es gibt hier einen komischen bug der die var array nach cbc entschlüssseln auf null pakt auser es ist in ner funktion drin
                fileoutput.write(array_zum_schreiben)
                # print("array vor dem first block",cyphertext_array)
                # es gibt hier einen komischen bug der die var array nach cbc entschlüssseln auf null pakt
                first_block = cyphertext_array[-64:]
                # print("array vorlen  append",cyphertext_array)
                array_liste.append(bytearray(fileinput.read(block_input_size)))

                string_for_progress = str(fileinput.tell()) + " of " + str(
                    max_size_in_bytes) + " bytes encrypted " + str(
                    ((100 / max_size_in_bytes) * fileinput.tell()) // 1) + "%"
                enty_result.delete(0, END)
                enty_result.insert(0, string_for_progress)
                root.update()
            if len(cyphertext_array) == 0 or len(cyphertext_array) < block_input_size:
                fileoutput.write(
                    local_cbc_mode_cypher_entschlüsseln(cyphertext_array, first_block, pw_liste_local_var, True))
                break
            del array_liste[0]

        fileoutput.close()
        fileinput.close()


class Hash_based_blockcypher():
    """benötigt import random,hashlib"""

    counter_array = bytearray()
    """nutze möglichst bald eine andere xor function die nach jemen stück ein byte aus demm array löscht. dann packe noch eine if schleife in die counter finction die auslöst das counter incement 1 wenn len counter array = 0 ist"""
    pw_array_liste = []

    def xor(self,a, b):
        if len(a) != len(b):
            raise Exception("array lengh for xor is uneven ",len(a)," ",len(b))
        #assert len(a) == len(b)
        output_array = []
        index_counter = 0
        integer_a = int.from_bytes(a,"big")
        integer_b = int.from_bytes(b,"big")

        xoredint = integer_a ^ integer_b
        return bytearray(int.to_bytes(xoredint,len(a),"big"))
        """
        for i in a:
            output_array.append(a[index_counter] ^ b[index_counter])
            index_counter += 1

        output_array = bytearray(output_array)
        return output_array
        """

    def pw_list_gen(self,pw_text_string):
        hashobj_for_konst = hashlib.sha3_512()
        """ranobj = random.SystemRandom()"""
        start_array = bytearray(pw_text_string, "UTF-8")
        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        konstant_start = bytearray("start","UTF-8")


        list_of_konstanst = []
        hashobj = hashlib.sha3_512()
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj_for_konst.update(konstant_start)
                konstant_start = hashobj_for_konst.digest()
                hashobj_for_konst = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            list_of_konstanst.append(konstant_start)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""

        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj.update(start_array + list_of_konstanst[rundencounter])
                start_array = hashobj.digest()
                hashobj = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            pw_list.append(start_array)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""
        self.pw_array_liste = pw_list

        return pw_list

    def get_rand_bytearray(self,length_in_bits):
        #assert length_in_bits % 8 == 0
        if length_in_bits % 8 != 0:
            raise Exception("cant get a random array with lenght 0")
        randobj = random.SystemRandom()
        randarray = bytearray()
        randarray = randarray + randobj.getrandbits(length_in_bits).to_bytes((length_in_bits // 8), "big")
        return randarray

    def text_input(self,):
        text_string = ""
        schleifen_var = False
        print("Bitte Text eingeben.Enter für Zeilen umbruch. Wenn Fertig Exit eingeben")
        while schleifen_var == False:
            teil_string = input()
            if teil_string == "Exit":
                schleifen_var = True
            else:
                text_string = text_string + teil_string + "\n"
        return text_string

    def festel_struktur_verschlüsseln(self, liste_pw_aray, aray_input_block):

        """
        #hier kommt eine feistel struktur hin. am anfang zum testen ist die f funktion ein xor. wen diese funktionirt dann kann sie durch eine hash funktion ersetzt werden
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))

        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8]:
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
        #return beispiel_block_array
        """

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_encyption(aray_input_block, liste_pw_aray)

    def festel_struktur_entschlüsseln(self, liste_pw_aray, aray_input_block):

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray)
        #aray_input_block = blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray[8:])

        """
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))
        #assert type(aray_input_block) == bytearray
        if type(aray_input_block) != bytearray:
            raise Exception("type aray_input_block is not bytearray, it is: ",type(aray_input_block))
        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8:-1]:
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()

        return beispiel_block_array
        """

    def counter_array_increment(self):
        neuer_counterstand = int.from_bytes(self.counter_array, "big")
        neuer_counterstand = (neuer_counterstand + 1) % pow(2,512)
        self.counter_array = neuer_counterstand.to_bytes(64,"big",)

    def get_new_rand_counter(self):
        randobj = random
        new_counter_array = 0
        new_counter_array = randobj.randint(0,(2**512))
        new_counter_array = new_counter_array.to_bytes(64,"big")
        self.counter_array = bytearray(new_counter_array)

    def counter_mode_mit_rand_counter(self,zu_verarbeitendes_array):
        """ist nur für einzelnen aufruf geeignet weil ansonsten die self.get rand counter als classenvar ausgelagert werden müsste"""
        zum_xor_zu_verwendeten_array = bytearray()
        self.get_new_rand_counter()
        rand_counter_und_output_array = bytearray(self.counter_array)
        """in zeile 118 darf das bytearray nicht entfernt werden weil sonst aus irgendeinem grund der counter wert nach incermentirung unten weiter gegeben wird"""
        #print("counter beim verschlüsseln ",self.counter_array)

        while len(zum_xor_zu_verwendeten_array) <= len(zu_verarbeitendes_array):
            block = self.festel_struktur_verschlüsseln(self.pw_array_liste,self.counter_array)
            zum_xor_zu_verwendeten_array = zum_xor_zu_verwendeten_array + block
            self.counter_array_increment()
        #print("xor element verschlüsseln ",zum_xor_zu_verwendeten_array)
        #print("pwliste verschlüsseln ",self.pw_array_liste)
        output = bytearray()
        #print(rand_counter_und_output_array)
        output = self.xor(zu_verarbeitendes_array,zum_xor_zu_verwendeten_array[0:len(zu_verarbeitendes_array)])
        rand_counter_und_output_array = rand_counter_und_output_array + output

        return rand_counter_und_output_array

    def counter_mode_mit_rand_counter_entschlüsseln(self, zu_verarbeitendes_array):
        zum_xor_zu_verwendeten_array = bytearray()
        self.counter_array = zu_verarbeitendes_array[0:64]
        #print(type(self.counter_array))
        zu_verarbeitendes_array = zu_verarbeitendes_array[64:]
        #print(len(zu_verarbeitendes_array))
        #print("counter beim entschlüsseln ", self.counter_array)


        while len(zum_xor_zu_verwendeten_array) <= len(zu_verarbeitendes_array):
            block = self.festel_struktur_verschlüsseln(self.pw_array_liste, self.counter_array)
            zum_xor_zu_verwendeten_array = zum_xor_zu_verwendeten_array + block
            self.counter_array_increment()
        #print("xor array entschlüsseln ",zum_xor_zu_verwendeten_array)
        #print("pwliste entschlüsseln ", self.pw_array_liste)
        output_array = bytearray()
        output_array = self.xor(zu_verarbeitendes_array, zum_xor_zu_verwendeten_array[0:len(zu_verarbeitendes_array)])


        return output_array

    def checksumm_anhängen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not bytearray. It is ",type(zu_verarbeitendes_array))
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array)
        checksum = shaobj.digest()
        zu_verarbeitendes_array = zu_verarbeitendes_array + checksum
        return zu_verarbeitendes_array


    def checksumm_prüfen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not bytearray. It is ",type(zu_verarbeitendes_array))
        erzugte_prüfsumme = bytearray()
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array[0:-32])
        erzugte_prüfsumme = shaobj.digest()


        if zu_verarbeitendes_array[-32:] == erzugte_prüfsumme:
            return True
        else:
            return False

class dh_austausch:

    #benötigt import random
    def expo_big(self, base, Expo, Mod):
        """
        int_liste = []
        ergebniss = 1
        while Expo != 0:
            if Expo % 2 == 1:
                int_liste.append(base)
            Expo = Expo // 2
            base = base ** 2
            base = base % Mod
        for i in int_liste:
            ergebniss = ergebniss * i
            ergebniss = ergebniss % Mod

        return ergebniss
        """
        return pow(base, Expo, Mod)

    def millerrabinprimetest(self,prime):
        """ teste ib input gerade ist oder unter 4 ist"""
        if prime < 4 or prime % 2 == 0:
            return False

        for i in range(2, 4, 1):
            fermet = pow(i, (prime - 1), prime)
            if fermet != 1 and fermet != (prime - 1):
                return False

        """forme Primzahl zu n -1 = d * (2**j)"""
        ist_float = False
        rando = random.SystemRandom()
        d = 0
        j = 0
        base = 2
        expo = 1
        m = prime - 1
        while ist_float == False:
            """ersetzte vileicht durch if m// (base ** expo) umkehren zu m  * (base ** expo. denn wenn es wieder m ergibt ist nicht gerundet worden"""
            if (m // (base ** expo)) * (base ** expo) == m:
                d = m // (base ** expo)
                j = expo
                expo += 1
            else:
                ist_float = True
        rundenzahl = 0
        while rundenzahl != 15:
            a = random.SystemRandom.randint(rando, 3, (prime - 2))
            if self.expo_big(a, d, prime) == 1 or self.expo_big(a, d, prime) == prime - 1:
                rundenzahl += 1
            else:
                einmal_true = True
                """ j is not allowed to be 0"""
                if j > 1:
                    for i in range(1, j, 1):
                        """diese schleife verursacht immer fehler beim raussuchen. muss überarbeitet werden"""
                        if self.expo_big(a, (d * (2 ** i)), prime) == prime - 1 and einmal_true == True:
                            rundenzahl += 1
                            einmal_true = False
                    if einmal_true != False:
                        return False

                elif j == 1 or j == 0:
                    if self.expo_big(a, (d * (2 ** 1)), prime) != prime - 1:
                        return False
                    else:
                        rundenzahl += 1
        return True

    def generation_dh_austausch(self,safe_prime,generator):
        #assert self.millerrabinprimetest(safe_prime) == True and self.millerrabinprimetest((safe_prime -1)//2) == True
        if self.millerrabinprimetest(safe_prime) != True or self.millerrabinprimetest((safe_prime -1)//2) != True:
            raise Exception("safe_prime is not a Safe-Prime")
        if generator < 2:
            raise Exception("generator can not be smaller than 2")

        Prime = safe_prime
        generator = generator
        zufal = random.SystemRandom()
        zufalszahl = zufal.randint(1, Prime)
        handshake = self.expo_big(generator, zufalszahl, Prime)
        liste_ergebnis = []
        liste_ergebnis.append(zufalszahl)
        liste_ergebnis.append(handshake)
        return liste_ergebnis

    def verarbeitung_dh_austausch(self,safe_prime,handshake,zufalszahl):
        #assert self.millerrabinprimetest(safe_prime) == True and self.millerrabinprimetest((safe_prime - 1) // 2) == True
        if self.millerrabinprimetest(safe_prime) != True or self.millerrabinprimetest((safe_prime - 1) // 2) != True:
            raise Exception("safe_prime is not a safe prime")


        safe_prime = int(safe_prime)
        handshake = int(handshake)
        zufalszahl = int(zufalszahl)
        gemeinsame_zahl = self.expo_big(handshake, zufalszahl, safe_prime)
        return gemeinsame_zahl

class dh_austausch_ohne_safe_prime_and_generator_check:

    #benötigt import random
    def expo_big(self, base, Expo, Mod):
        """
        int_liste = []
        ergebniss = 1
        while Expo != 0:
            if Expo % 2 == 1:
                int_liste.append(base)
            Expo = Expo // 2
            base = base ** 2
            base = base % Mod
        for i in int_liste:
            ergebniss = ergebniss * i
            ergebniss = ergebniss % Mod

        return ergebniss
        """
        return pow(base, Expo, Mod)

    def generation_dh_austausch(self,safe_prime,generator):
        #assert self.millerrabinprimetest(safe_prime) == True and self.millerrabinprimetest((safe_prime -1)//2) == True

        if generator < 2:
            raise Exception("generator can not be smaller than 2")

        Prime = safe_prime
        generator = generator
        zufal = random.SystemRandom()
        zufalszahl = zufal.randint(1, Prime)
        handshake = self.expo_big(generator, zufalszahl, Prime)
        liste_ergebnis = []
        liste_ergebnis.append(zufalszahl)
        liste_ergebnis.append(handshake)
        return liste_ergebnis

    def verarbeitung_dh_austausch(self,safe_prime,handshake,zufalszahl):
        #assert self.millerrabinprimetest(safe_prime) == True and self.millerrabinprimetest((safe_prime - 1) // 2) == True



        safe_prime = int(safe_prime)
        handshake = int(handshake)
        zufalszahl = int(zufalszahl)
        gemeinsame_zahl = self.expo_big(handshake, zufalszahl, safe_prime)
        return gemeinsame_zahl

class SchnorrSig:

    """benotigt import hashlib,rand"""

    def expo_big(self, base, Expo, Mod):
        """
        int_liste = []
        ergebniss = 1
        while Expo != 0:
            if Expo % 2 == 1:
                int_liste.append(base)
            Expo = Expo // 2
            base = base ** 2
            base = base % Mod
        for i in int_liste:
            ergebniss = ergebniss * i
            ergebniss = ergebniss % Mod

        return ergebniss
        """
        return pow(base, Expo, Mod)

    def millerrabinprimetest(self,prime):
        #assert type(prime) == int
        if type(prime) != int:
            raise Exception("type prime is not int. It is ",type(prime))
        """ teste ib input gerade ist oder unter 4 ist"""
        if prime < 4 or prime % 2 == 0:
            return False

        """forme Primzahl zu n -1 = d * (2**j)"""
        ist_float = False
        rando = random.SystemRandom()
        d = 0
        j = 0
        base = 2
        expo = 1
        m = prime - 1
        while ist_float == False:
            """ersetzte vileicht durch if m// (base ** expo) umkehren zu m  * (base ** expo. denn wenn es wieder m ergibt ist nicht gerundet worden"""
            if (m // (base ** expo)) * (base ** expo) == m:
                d = m // (base ** expo)
                j = expo
                expo += 1
            else:
                ist_float = True
        rundenzahl = 0
        while rundenzahl != 50:
            a = random.SystemRandom.randint(rando, 3, (prime - 2))
            if self.expo_big(a, d, prime) == 1 or self.expo_big(a, d, prime) == prime - 1:
                rundenzahl += 1
            else:
                einmal_true = True
                """ j is not allowed to be 0"""
                if j > 1:
                    for i in range(1, j, 1):
                        """diese schleife verursacht immer fehler beim raussuchen. muss überarbeitet werden"""
                        if self.expo_big(a, (d * (2 ** i)), prime) == prime - 1 and einmal_true == True:
                            rundenzahl += 1
                            einmal_true = False
                    if einmal_true != False:
                        return False

                elif j == 1 or j == 0:
                    if self.expo_big(a, (d * (2 ** 1)), prime) != prime - 1:
                        return False
                    else:
                        rundenzahl += 1
        return True

    def Textsig(self, Text, privatekey, Prime,generator):
        #assert type(Text) == str
        if type(Text) != str:
            raise Exception("type Text is not str. It is ",type(Text))
        #assert type(privatekey) == int
        if type(privatekey) != int:
            raise Exception("type privatekey is not int. It is ",type(privatekey))
        #assert type(Prime) == int
        if type(Prime) != int:
            raise Exception("type Prime is not int. It is ",type(Prime))
        #assert type(generator) == int
        if type(generator) != int:
            raise Exception("type generator is not int. It is ",type(generator))
        if generator < 2:
            raise Exception("Generator can not be smaller than 2")
        rand = random
        rand_var = random.SystemRandom.randint(rand, 1, Prime)
        Teilsig_1 = self.expo_big(generator, rand_var, Prime)
        """Randvar darf nie!!! 2 mal verwendet werden da sonst die sicherheit trivial  gebrochen wird"""
        hashvar = hashlib.sha512()
        hashvar.update(bytearray(str(Teilsig_1), "UTF-8"))

        hashvar.update(bytearray(Text, "Utf-8"))
        """nun das ergebnis von hashvar digest in eine int umwandeln. nutze int.from_byte"""
        hashoutput = hashvar.digest()
        hashoutput = int.from_bytes(hashoutput, "big")
        Teilsig_2 = ((hashoutput * privatekey) + rand_var) % ((Prime - 1) // 2)

        """ersetze bald wenn möglich print mit return von zb einer liste"""

        print("Generator:", generator, "\nPrime:", Prime, "\nHash:Sha512")
        print("Nachricht:")
        print(Text)
        print("Teilsignatur 1:\n", Teilsig_1, "\nTeilsignatur 2:\n", Teilsig_2)
        liste_ergebnnis = []
        liste_ergebnnis.append(Teilsig_1)
        liste_ergebnnis.append(Teilsig_2)
        return  liste_ergebnnis

    def Signaturvery(self, Text, Teilsig1, Teilsig2, Publickey, Prime,Generator):
        #assert type(Text) == str
        if type(Text) != str:
            raise Exception("type Text is not str. It is ",type(Text))
        #assert type(Teilsig1) == int
        if type(Teilsig1) != int:
            raise Exception("type Teilsig1 is not int. It is ",type(Teilsig1))
        #assert type(Teilsig2) == int
        if type(Teilsig2) != int:
            raise Exception("type Teilsig2 is not int. It is ",type(Teilsig2))
        #assert type(Publickey) == int
        if type(Publickey) != int:
            raise Exception("type Publikkey is not int. It is ",type(Publickey))
        #assert type(Prime) == int:
        if type(Prime) != int:
            raise Exception("type Prime is not int. It is ",type(Prime))
        if Generator < 2:
            raise Exception("Generator can not be smaller than 2")

        "Prüfen der signatur"
        #print("Es steht nur Sha512 zur verfügung")
        generator = Generator
        #print("2 ist der standart genarator")
        ist_Prime = False
        while ist_Prime == False:

            if self.millerrabinprimetest(Prime) == True:
                if self.millerrabinprimetest(((Prime - 1) // 2)) == True:
                    ist_Prime = True
                else:
                    #print("Warnung die angegebene Zahl ist keine Safe-Prime")
                    #input("belibige taste drücken:")
                    ist_Prime = True

            else:
                print("eingegebene Zahl wahr keine sichere Primzahl")

        """wenn richtwert 1 == Richtwert 2 dan ist die signatur richtig"""
        Richtwert_1 = self.expo_big(generator, Teilsig2, Prime)
        """nun expo berechnung für richtwert 2"""
        hashvar = hashlib.sha512()
        hashvar.update(bytearray(str(Teilsig1), "UTF-8"))
        hashvar.update(bytearray(Text, "Utf-8"))
        """nun das ergebnis von hashvar digest in eine int umwandeln. nutze int.from_byte"""
        hashoutput = hashvar.digest()
        hashoutput = int.from_bytes(hashoutput, "big")

        Richtwert_2 = (pow(Publickey, hashoutput, Prime) * Teilsig1) % Prime

        print(Richtwert_1, "\n", Richtwert_2)
        if Richtwert_1 == Richtwert_2:
            #print("Signatur ist korrekt")
            string = "Signature is correct"
            return string
        else:
            #print("Signatur ist Falsch")
            string = "Signature is incorrect"
            return string

    def schorr_key_erstellen(self,safe_prime,generator):

        #assert type(safe_prime) == int
        if type(safe_prime) != int:
            raise Exception("type safe_prime is not int. It is ",type(safe_prime))
        #assert type(generator) == int
        if type(generator) != int:
            raise Exception("type generator is not int. it is ",type(generator))
        if generator < 2:
            raise Exception("Generator can not be smaller than 2")
        #assert self.millerrabinprimetest(safe_prime) == True:
        if self.millerrabinprimetest(safe_prime) != True:
            raise Exception("safe_prime is not a safe prime")
        #assert self.millerrabinprimetest(((safe_prime - 1) // 2)) == True
        if self.millerrabinprimetest(((safe_prime - 1) // 2)) != True:
            raise Exception("safe_prime is not a safe prime")

        rand = random.SystemRandom()
        primeminusone = safe_prime - 1
        private_key = rand.randint(1, primeminusone)
        public_key = self.expo_big(generator, private_key, safe_prime)
        liste_ergbenis = []
        liste_ergbenis.append(private_key)
        liste_ergbenis.append(public_key)
        return liste_ergbenis

class SchnorrSig_with_no_safty_prime_and_gen_check:

    """benotigt import hashlib,rand"""

    def expo_big(self, base, Expo, Mod):
        """
        int_liste = []
        ergebniss = 1
        while Expo != 0:
            if Expo % 2 == 1:
                int_liste.append(base)
            Expo = Expo // 2
            base = base ** 2
            base = base % Mod
        for i in int_liste:
            ergebniss = ergebniss * i
            ergebniss = ergebniss % Mod

        return ergebniss
        """
        return pow(base, Expo, Mod)

    def Textsig(self, Text, privatekey, Prime,generator):
        #assert type(Text) == str
        if type(Text) != str:
            raise Exception("type Text is not str. It is ",type(Text))
        #assert type(privatekey) == int
        if type(privatekey) != int:
            raise Exception("type privatekey is not int. It is ",type(privatekey))
        #assert type(Prime) == int
        if type(Prime) != int:
            raise Exception("type Prime is not int. It is ",type(Prime))
        #assert type(generator) == int
        if type(generator) != int:
            raise Exception("type generator is not int. It is ",type(generator))
        if generator < 2:
            raise Exception("Generator can not be smaller than 2")
        rand = random
        rand_var = random.SystemRandom.randint(rand, 1, Prime)
        Teilsig_1 = self.expo_big(generator, rand_var, Prime)
        """Randvar darf nie!!! 2 mal verwendet werden da sonst die sicherheit trivial  gebrochen wird"""
        hashvar = hashlib.sha512()
        hashvar.update(bytearray(str(Teilsig_1), "UTF-8"))

        hashvar.update(bytearray(Text, "Utf-8"))
        """nun das ergebnis von hashvar digest in eine int umwandeln. nutze int.from_byte"""
        hashoutput = hashvar.digest()
        hashoutput = int.from_bytes(hashoutput, "big")
        Teilsig_2 = ((hashoutput * privatekey) + rand_var) % ((Prime - 1) // 2)

        """ersetze bald wenn möglich print mit return von zb einer liste"""

        print("Generator:", generator, "\nPrime:", Prime, "\nHash:Sha512")
        print("Nachricht:")
        print(Text)
        print("Teilsignatur 1:\n", Teilsig_1, "\nTeilsignatur 2:\n", Teilsig_2)
        liste_ergebnnis = []
        liste_ergebnnis.append(Teilsig_1)
        liste_ergebnnis.append(Teilsig_2)
        return  liste_ergebnnis

    def Signaturvery(self, Text, Teilsig1, Teilsig2, Publickey, Prime,Generator):
        #assert type(Text) == str
        if type(Text) != str:
            raise Exception("type Text is not str. It is ",type(Text))
        #assert type(Teilsig1) == int
        if type(Teilsig1) != int:
            raise Exception("type Teilsig1 is not int. It is ",type(Teilsig1))
        #assert type(Teilsig2) == int
        if type(Teilsig2) != int:
            raise Exception("type Teilsig2 is not int. It is ",type(Teilsig2))
        #assert type(Publickey) == int
        if type(Publickey) != int:
            raise Exception("type Publikkey is not int. It is ",type(Publickey))
        #assert type(Prime) == int:
        if type(Prime) != int:
            raise Exception("type Prime is not int. It is ",type(Prime))
        if Generator < 2:
            raise Exception("Generator can not be smaller than 2")

        "Prüfen der signatur"
        #print("Es steht nur Sha512 zur verfügung")
        generator = Generator
        #print("2 ist der standart genarator")


        """wenn richtwert 1 == Richtwert 2 dan ist die signatur richtig"""
        Richtwert_1 = self.expo_big(generator, Teilsig2, Prime)
        """nun expo berechnung für richtwert 2"""
        hashvar = hashlib.sha512()
        hashvar.update(bytearray(str(Teilsig1), "UTF-8"))
        hashvar.update(bytearray(Text, "Utf-8"))
        """nun das ergebnis von hashvar digest in eine int umwandeln. nutze int.from_byte"""
        hashoutput = hashvar.digest()
        hashoutput = int.from_bytes(hashoutput, "big")

        Richtwert_2 = (pow(Publickey, hashoutput, Prime) * Teilsig1) % Prime

        print(Richtwert_1, "\n", Richtwert_2)
        if Richtwert_1 == Richtwert_2:
            #print("Signatur ist korrekt")
            string = "Signature is correct"
            return string
        else:
            #print("Signatur ist Falsch")
            string = "Signature is incorrect"
            return string

    def schorr_key_erstellen(self,safe_prime,generator):

        #assert type(safe_prime) == int
        if type(safe_prime) != int:
            raise Exception("type safe_prime is not int. It is ",type(safe_prime))
        #assert type(generator) == int
        if type(generator) != int:
            raise Exception("type generator is not int. it is ",type(generator))
        if generator < 2:
            raise Exception("Generator can not be smaller than 2")


        rand = random.SystemRandom()
        primeminusone = safe_prime - 1
        private_key = rand.randint(1, primeminusone)
        public_key = self.expo_big(generator, private_key, safe_prime)
        liste_ergbenis = []
        liste_ergbenis.append(private_key)
        liste_ergbenis.append(public_key)
        return liste_ergbenis

class Hash_based_blockcypher_und_Textdatei():
    """benötigt import random,hashlib"""

    counter_array = bytearray()
    """nutze möglichst bald eine andere xor function die nach jemen stück ein byte aus demm array löscht. dann packe noch eine if schleife in die counter finction die auslöst das counter incement 1 wenn len counter array = 0 ist"""
    pw_array_liste = []

    def xor(self,a, b):
        #assert len(a) == len(b)
        if len(a) != len(b):
            raise Exception("Fehler beim xor,  die längen sind unterschielich\n", len(a), " ", len(b))
            print("Fehler beim xor,  die längen sind unterschielich\n", len(a), " ", len(b))
            return False
        output_array = []
        index_counter = 0
        for i in a:
            output_array.append(a[index_counter] ^ b[index_counter])
            index_counter += 1

        output_array = bytearray(output_array)
        return output_array
    def pw_list_gen(self,pw_text_string):
        hashobj_for_konst = hashlib.sha3_512()
        """ranobj = random.SystemRandom()"""
        start_array = bytearray(pw_text_string, "UTF-8")
        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        konstant_start = bytearray("start","UTF-8")


        list_of_konstanst = []
        hashobj = hashlib.sha3_512()
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj_for_konst.update(konstant_start)
                konstant_start = hashobj_for_konst.digest()
                hashobj_for_konst = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            list_of_konstanst.append(konstant_start)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""

        rundencounter = 0
        pw_deriv_counter = 0
        pw_list = []
        while rundencounter != 36:
            while pw_deriv_counter != 30000:
                pw_deriv_counter = pw_deriv_counter + 1
                hashobj.update(start_array + list_of_konstanst[rundencounter])
                start_array = hashobj.digest()
                hashobj = hashlib.sha3_512()
                """print(rundencounter," ",pw_deriv_counter)"""
            pw_list.append(start_array)
            rundencounter += 1
            pw_deriv_counter = 0
        """PW liste hat anzahl einträge rundencounter und jeweils eine länge von 512bit oder 64 byte"""
        Hash_based_blockcypher_und_Textdatei.pw_array_liste = pw_list

        return pw_list


    def get_rand_bytearray(self,length_in_bits):
        #assert length_in_bits % 8 == 0
        if length_in_bits % 8 != 0:
            raise Exception("lenght_in_bits must be a muliple of 8")
        randobj = random.SystemRandom()
        randarray = bytearray()
        randarray = randarray + randobj.getrandbits(length_in_bits).to_bytes((length_in_bits // 8), "big")
        return randarray

    def text_input(self,):
        text_string = ""
        schleifen_var = False
        print("Bitte Text eingeben.Enter für Zeilen umbruch. Wenn Fertig Exit eingeben")
        while schleifen_var == False:
            teil_string = input()
            if teil_string == "Exit":
                schleifen_var = True
            else:
                text_string = text_string + teil_string + "\n"
        return text_string

    def festel_struktur_verschlüsseln(self, liste_pw_aray, aray_input_block):

        """
        #hier kommt eine feistel struktur hin. am anfang zum testen ist die f funktion ein xor. wen diese funktionirt dann kann sie durch eine hash funktion ersetzt werden
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))

        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8]:
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
        #return beispiel_block_array
        """

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_encyption(aray_input_block, liste_pw_aray)

    def festel_struktur_entschlüsseln(self, liste_pw_aray, aray_input_block):

        blockobj = block_cypher_parts()
        return blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray)
        #aray_input_block = blockobj.ARX_cypher_one_round_decyption(aray_input_block, liste_pw_aray[8:])

        """
        #assert len(aray_input_block) == 64
        if len(aray_input_block) != 64:
            raise Exception("array lenght is not 64 bytes, it is ",len(aray_input_block))
        #assert type(aray_input_block) == bytearray
        if type(aray_input_block) != bytearray:
            raise Exception("type aray_input_block is not bytearray, it is: ",type(aray_input_block))
        beispiel_block_array = aray_input_block
        hashobj = hashlib.sha256()

        for i in liste_pw_aray[0:8:-1]:
            hashobj.update(beispiel_block_array[0:32])
            hashobj.update(i[32:64])
            beispiel_block_array[32:64] = self.xor(beispiel_block_array[32:64], hashobj.digest())
            hashobj = hashlib.sha256()
            #XOR KANN NICHT BLOCKWEISE GEHEN MUST IN NER WHILE SCHLEIFE UND COUNTER DIE EINZELNEN ZUEINANDER XOREN
            hashobj.update(beispiel_block_array[32:64])
            hashobj.update(i[0:32])
            beispiel_block_array[0:32] = self.xor(beispiel_block_array[0:32], hashobj.digest())
            hashobj = hashlib.sha256()

        return beispiel_block_array
        """


    def counter_array_increment(self):
        neuer_counterstand = int.from_bytes(self.counter_array, "big")
        neuer_counterstand = (neuer_counterstand + 1) % pow(2,512)
        self.counter_array = neuer_counterstand.to_bytes(64,"big",)

    def get_new_rand_counter(self):
        randobj = random
        new_counter_array = 0
        new_counter_array = randobj.randint(0,(2**512))
        new_counter_array = new_counter_array.to_bytes(64,"big")
        self.counter_array = bytearray(new_counter_array)

    def counter_mode_mit_rand_counter(self,zu_verarbeitendes_array):
        """ist nur für einzelnen aufruf geeignet weil ansonsten die self.get rand counter als classenvar ausgelagert werden müsste"""
        zum_xor_zu_verwendeten_array = bytearray()
        self.get_new_rand_counter()
        rand_counter_und_output_array = bytearray(self.counter_array)
        """in zeile 118 darf das bytearray nicht entfernt werden weil sonst aus irgendeinem grund der counter wert nach incermentirung unten weiter gegeben wird"""
        #print("counter beim verschlüsseln ",self.counter_array)

        while len(zum_xor_zu_verwendeten_array) <= len(zu_verarbeitendes_array):
            block = self.festel_struktur_verschlüsseln(self.pw_array_liste,self.counter_array)
            zum_xor_zu_verwendeten_array = zum_xor_zu_verwendeten_array + block
            self.counter_array_increment()
        #print("xor element verschlüsseln ",zum_xor_zu_verwendeten_array)
        #print("pwliste verschlüsseln ",self.pw_array_liste)
        output = bytearray()
        #print(rand_counter_und_output_array)
        output = self.xor(zu_verarbeitendes_array,zum_xor_zu_verwendeten_array[0:len(zu_verarbeitendes_array)])
        rand_counter_und_output_array = rand_counter_und_output_array + output

        return rand_counter_und_output_array

    def counter_mode_mit_rand_counter_entschlüsseln(self, zu_verarbeitendes_array):
        zum_xor_zu_verwendeten_array = bytearray()
        self.counter_array = zu_verarbeitendes_array[0:64]
        #print(type(self.counter_array))
        zu_verarbeitendes_array = zu_verarbeitendes_array[64:]
        #print(len(zu_verarbeitendes_array))
        #print("counter beim entschlüsseln ", self.counter_array)


        while len(zum_xor_zu_verwendeten_array) <= len(zu_verarbeitendes_array):
            block = self.festel_struktur_verschlüsseln(self.pw_array_liste, self.counter_array)
            zum_xor_zu_verwendeten_array = zum_xor_zu_verwendeten_array + block
            self.counter_array_increment()
        #print("xor array entschlüsseln ",zum_xor_zu_verwendeten_array)
        #print("pwliste entschlüsseln ", self.pw_array_liste)
        output_array = bytearray()
        output_array = self.xor(zu_verarbeitendes_array, zum_xor_zu_verwendeten_array[0:len(zu_verarbeitendes_array)])


        return output_array

    def checksumm_anhängen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not bytearray. It is ",type(zu_verarbeitendes_array))
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array)
        checksum = shaobj.digest()
        zu_verarbeitendes_array = zu_verarbeitendes_array + checksum
        return zu_verarbeitendes_array

    def checksumm_prüfen_sha256(self,zu_verarbeitendes_array):
        #assert type(zu_verarbeitendes_array) == bytearray
        if type(zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not bytearray. It is ",type(zu_verarbeitendes_array))
        erzugte_prüfsumme = bytearray()
        shaobj = hashlib.sha3_256()
        shaobj.update(zu_verarbeitendes_array[0:-32])
        erzugte_prüfsumme = shaobj.digest()


        if zu_verarbeitendes_array[-32:] == erzugte_prüfsumme:
            return True
        else:
            return False

    def prüfsumme_erzeugen_8byte(self,block_array):
        #assert type(block_array) == bytearray
        if type(block_array) != bytearray:
            raise Exception("type block_array is not bytearray. It is ",type(block_array))
        """es reicht ein kleiner teil der summe wie im kommentar der funktion zusammenfügen block erwäht
        reichen 8byte"""
        hashobj = hashlib.sha3_512()
        hashobj.update(block_array)
        prüfsumme = hashobj.digest()
        prüfsumme = prüfsumme[0:8]
        return prüfsumme

    def prüfsumme_testen_8byte(self,block_array):
        #assert type(block_array) == bytearray
        if type(block_array) != bytearray:
            raise Exception("type block_array is not bytearray. It is ",type(block_array))
        #assert len(block_array) == 64
        if len(block_array) != 64:
            raise Exception("len block array must be 65. it is ",len(block_array))
        hashobj = hashlib.sha3_512()
        hashobj.update(block_array[0:56])
        prüfsumme = hashobj.digest()
        prüfsumme = prüfsumme[0:8]

        if prüfsumme == block_array[56:]:
            return True
        else:
            return False

    def write_array_in_Textdatei(self,zu_zu_verarbeitendes_array):
        #assert type(zu_zu_verarbeitendes_array) == bytearray
        if type(zu_zu_verarbeitendes_array) != bytearray:
            raise Exception("type zu_verarbeitendes_array is not bytearray. It is ",type(zu_zu_verarbeitendes_array))

        fileobj = open("Base.txt","a")
        hex_aus_array = bytearray.hex(zu_zu_verarbeitendes_array)
        fileobj.write(hex_aus_array)
        fileobj.write("\n")
        fileobj.close()

    def padding_zu_scheibendes_arrray_and_checksum(self,block_array):
        #assert type(block_array) == bytearray
        if type(block_array) != bytearray:
            raise Exception("type block_array is not bytearray. it is ",type(block_array))
        array_list = []



        #first 8 byte for randpadding
        #min padding 01 2 bytes
        #secound up to 46 byte for text
        #thierd 8bytes checksum

        #schritt eins: teile das blockarray in längen von maximal 46byte

        while len(block_array) > 46:
            array_list.append(block_array[0:46])
            block_array = block_array[46::]
        if len(block_array) != 0:
            array_list.append(block_array)

        for i in array_list:
            assert len(i) <= 46


        #füge an den anfang jedes arrays in dieser liste das anfangspaddingrand zu
        array_liste_nach_rand_padding = []
        for i in array_list:
            randpadding = random.SystemRandom.getrandbits("",64).to_bytes(8,"big")
            newblock = randpadding + i
            array_liste_nach_rand_padding.append(newblock)


        #füge das minpadding bei jdem element in der liste zu
        array_list_after_minimal_padding = []
        minimalpadding = bytearray("10","UTF-8")
        for i in array_liste_nach_rand_padding:
            newblock = i + minimalpadding
            array_list_after_minimal_padding.append(newblock)
        #print(array_liste_nach_rand_padding)




        #die elemente die noch nicht 56 byte lang sind so lange "0" as byte array hinzufügen bis die diese länge ereichen

        array_liste_lengh_check = []

        for i in array_list_after_minimal_padding:
            while len(i) != 56:

                i = i + bytearray("0","UTF-8")
            array_liste_lengh_check.append(i)

        #nun jedem element die 8byte checksum dranpacken. nun sind die arrays in der list alle 64byte lang und damit mit dem blockcypher verschlüsselbar
        array_liste_lengh_checkrayy_liste_64_bytes = []
        newblock = bytearray()

        for i in array_liste_lengh_check:
            assert len(i) == 56
            #print("zeile 271  type and i: ",type(i)," ",i)
            newblock = i + Hash_based_blockcypher_und_Textdatei.prüfsumme_erzeugen_8byte("",bytearray(i))
            assert len(newblock) == 64
            array_liste_lengh_checkrayy_liste_64_bytes.append(bytearray(newblock))






        #return liste dieser vorgefertigten elemente
        return array_liste_lengh_checkrayy_liste_64_bytes

    def read_array_list_aus_Textdatei(self):
        fileobj = open("Base.txt", "a")
        fileobj.close()

        fileobj = open("Base.txt", "r")
        filesstringdic = []


        for i in str.split(fileobj.read(),"\n"):
            if i != "":
                try:
                    filesstringdic.append(bytearray.fromhex(i))
                except:
                    pass

        return filesstringdic

    def encryption_block_append_checksum_and_write_to_file(self,plaintext_array,password_string):
        #assert type(plaintext_array) == bytearray
        if type(plaintext_array) != bytearray:
            raise Exception("type plaintext_array is not bytearray.It is ",type(plaintext_array))
        #assert type(password_string) == str
        if type(password_string) != str:
            raise Exception("type password_string is not str. It is ",type(password_string))
        pw_list = Hash_based_blockcypher_und_Textdatei.pw_list_gen("",password_string)
        liste_arrays_for_encryption = []
        liste_arrays_for_encryption = Hash_based_blockcypher_und_Textdatei.padding_zu_scheibendes_arrray_and_checksum("",plaintext_array)

        liste_cyphertext = []
        #print("zeile 312 problem entwerder pw liste oder array:",liste_arrays_for_encryption)
        #print(pw_list)
        hashobj = Hash_based_blockcypher_und_Textdatei()
        for i in liste_arrays_for_encryption:
            liste_cyphertext.append(hashobj.festel_struktur_verschlüsseln(pw_list,i))

        for i in liste_cyphertext:
            Hash_based_blockcypher_und_Textdatei.write_array_in_Textdatei("",i)

    def decrypt_checksumcheck_from_file(self,password_string):
        #assert type(password_string) == str
        if type(password_string) != str:
            raise Exception("type password_string is not str. It is ",type(password_string))
        pw_liste = Hash_based_blockcypher_und_Textdatei.pw_list_gen("",password_string)

        array_liste_aus_file = Hash_based_blockcypher_und_Textdatei.read_array_list_aus_Textdatei("")
        decrypted_array_list = []
        #die liste muss durchlaufen werded

        #schritt 1: decrypt  64 byte eintrag,andere längen ignoriren weil es sonst zu fehler beim blockcypher führt
        for i in array_liste_aus_file:
            if len(i) == 64:
                i = self.festel_struktur_entschlüsseln(pw_liste,i)
                decrypted_array_list.append(i)

        #schritt 2:teste ob die 8bit checkksum im array richtig ist
        array_liste_nach_checksum = []
        for i in decrypted_array_list:
            if self.prüfsumme_testen_8byte(i) == True:
                array_liste_nach_checksum.append(i)
        #print(array_liste_nach_checksum)
        #leider lehr teste oder ändere prüfen_teste_8byte :solved


        #schritt 3:wenn richtig entferne checksum und rand padding 8byte am anfang
        array_liste_nach_padding_und_checksum_entfernung = []
        for i in array_liste_nach_checksum:
            i = i[8:56]
            assert len(i) == 48
            array_liste_nach_padding_und_checksum_entfernung.append(i)

        #schritt 4: entferne das "10" er padding in einer schleife die von rechtes nach links bis zur ersten "1" alles  einschlislich der "1" entfernt,
        array_liste_nach_padding_entfernung10 = []
        #print(array_liste_nach_padding_und_checksum_entfernung)
        #fehler beim entfernen des 10 noch nicht behiben # behoben
        for i in array_liste_nach_padding_und_checksum_entfernung:
            i = str(i,"UTF-8")

            i = i[::-1]
            for buchstabe in i:
                #print(i, "\n ",buchstabe)
                assert buchstabe == "0" or buchstabe == "1" # wenn fehler dann falsche einsen nuller padding
                if buchstabe == "0":
                    i = i[1:]
                elif buchstabe == "1":
                    i = i[1:]
                    i = i[::-1]
                    array_liste_nach_padding_entfernung10.append(i)
                    break



        #schritt 5: nun die stringelemente in der liste zu einem ganzen string zusammenfügen und dem nutzer herausgeben
        gesammt_str = ""
        for i in array_liste_nach_padding_entfernung10:
            gesammt_str = gesammt_str + i

        return gesammt_str

    def overwrite_text_with_password(self,password_string):
        #128 bytes fur denn text. 1 byte fur das \n sonderzeichen
        #assert type(password_string) == str
        if type(password_string) != str:
            raise Exception("type password_string is not str. It is ",type(password_string))



        fileobj = open("Base.txt", "a")
        fileobj.close()

        fileobj = open("Base.txt", "r")
        filesstringdic = []
        zeilen_liste_mit_positivem_checksum_test = []
        zeilen_counter = 1

        pw_array = self.pw_list_gen(password_string)
        for i in str.split(fileobj.read(),"\n"):
            if i != "":
                print("i :",i)
                try:
                    filearay = bytearray.fromhex(i)
                    array_zum_prufen = self.festel_struktur_entschlüsseln(pw_array, filearay)
                    print(array_zum_prufen)
                    print(self.prüfsumme_testen_8byte(array_zum_prufen))
                    if self.prüfsumme_testen_8byte(array_zum_prufen) == True:
                        zeilen_liste_mit_positivem_checksum_test.append(zeilen_counter)
                except:
                    #print("not hex: ",i)
                    pass
                zeilen_counter = zeilen_counter + 1

                #benötigt noch einen counter der sowohl bei einer exeption als auch bei einer False bei der prüfsumme die zeile notiert


                #die zeilen wo die 8 byte teste true ergeben in liste sammeln . am ende der funktfionen file. open "wb" nehmen und die jeweiligen zeilwen 18ter schritten ablaufen. 128 file der 129te \n sonderzeichen
                #versuche das lieber über eine liste zu machen . dort kannst du die texte ersetzten oder überspringen. am ende wird die ganze datei mit dem gesamten inhalt der liste überschrieben.

        #print(zeilen_liste_mit_positivem_checksum_test)
        fileobj.close()

        hasobj = Hash_based_blockcypher_und_Textdatei()
        fileobj = open("Base.txt", "rb+")
        zeilen_counter = 1
        ist_zeileumbruch = False
        while len(zeilen_liste_mit_positivem_checksum_test) != 0:

            if zeilen_counter == zeilen_liste_mit_positivem_checksum_test[0]:
                hexa_string = str(hasobj.get_rand_bytearray(512).hex())
                hex_aray_from_utf_8 = bytearray(hexa_string,"UTF-8")

                fileobj.write(hex_aray_from_utf_8)
                fileobj.write(bytearray("\n","UTF-8"))
                del zeilen_liste_mit_positivem_checksum_test[0]

            else:
                while ist_zeileumbruch == False:
                    str_var = str(fileobj.read(1),"UTF-8")
                    if str_var == "\n" or len(str_var) == 0:
                        ist_zeileumbruch = True
            zeilen_counter = zeilen_counter + 1
            ist_zeileumbruch = False

        fileobj.close()

    def write_rand_blocks_to_file(self,nummber_of_blogs_to_write):
        #assert type(nummber_of_blogs_to_write) == int
        if type(nummber_of_blogs_to_write) != int:
            raise Exception("type nummber_of_blogs_to_write is not int. It is ",type(nummber_of_blogs_to_write))
        #assert nummber_of_blogs_to_write > 0
        if nummber_of_blogs_to_write < 0:
            raise Exception("Nummer of blocks must be greater than 1")

        randblockarray = bytearray()
        randkey = bytearray()



        written_block_counter = 0
        while nummber_of_blogs_to_write != written_block_counter:
            randkey = self.get_rand_bytearray(512)
            randkey = randkey.hex()
            randblockarray = self.get_rand_bytearray(512)
            password_liste_fur_crypt = self.pw_list_gen(str(randkey))
            self.write_array_in_Textdatei(self.festel_struktur_verschlüsseln(password_liste_fur_crypt,randblockarray))

            written_block_counter = written_block_counter + 1

class Hauptmenü_grid(Tk):
    liste_hauptmenü_obj = []

    def menü_1(self):

        rootmenu = Menu(self,bg=menu_and_button_color,activebackground=menu_and_button_color,activeborderwidth=0)
        self.config(menu=rootmenu)
        menue = Menu(rootmenu)
        menue_DH = Menu(rootmenu)
        menue_sig = Menu(rootmenu)



        rootmenu.add_cascade(label="Modules", menu=menue)
        rootmenu.add_cascade(label="Signature", menu=menue_sig)
        rootmenu.add_cascade(label="Diffie–Hellman key exchange",menu=menue_DH)


        menue.add_command(label="Safe Prime Generator", command=lambda: Seite_Safe_Prime_gen.prime_menü(self))
        menue_sig.add_command(label="Schnorrsig verifying", command=lambda: Seite_Schnorr_sig_Prüfen.menü(self))
        menue_sig.add_command(label="Schnorrsig creator", command=lambda: Seite_Schnorr_sig_erstellen.menü(self))
        menue_sig.add_command(label="Manual Schnorr Key_Pair generator", command=lambda: Seite_Schnorr_Schlüsselpaar_erstellen.menü(self))
        menue_sig.add_command(label="Recommended Schnorr Key_Par generator with static safeprime and generator",command=lambda : Seite_Schnorr_Schlüsselpaar_erstellen_mit_statischen_var.menü(self))
        menue_DH.add_command(label="Recommended DH exchange generator with static safeprime and generator", command=lambda: Seite_DH_Austausch_erzeugen_mit_statischen_var.menü(self))
        menue_DH.add_command(label="Recommended DH exchange processor with static safeprime",command=lambda: Seite_DH_Austausch_verarbeiten_mit_statischen_var.menü(self))
        menue_DH.add_command(label="Manual DH exchange generator", command=lambda: Seite_DH_Austausch_erzeugen.menü(self))
        menue_DH.add_command(label="Manual DH exchange processor", command=lambda: Seite_DH_Austausch_verarbeiten.menü(self))
        menue.add_command(label="Text de/encryption", command=lambda: Seite_Symetrische_Text_Ver_und_Entschlüsselung.menü(self))
        menue.add_command(label="Hash from data",command=lambda: Seite_hash_from_data.hash_menu(self))
        menue.add_command(label="Data de/encryption", command=lambda: Seite_data_encryption_decryption.data_menu(self))
        menue.add_command(label="Read/write text to secured file", command=lambda: Seite_write_read_text_for_to_secure_safe.text_safe_menü(self))
        menue.add_command(label="Licence and Info", command=lambda: Seite_Licence_and_info.info_menu(self))




        for i in self.grid_slaves():
            Hauptmenü_grid.liste_hauptmenü_obj.append(i)

    def destroy_obj(self):
        for i in self.grid_slaves():
            #i.destroy()
            if i not in Hauptmenü_grid.liste_hauptmenü_obj:
                i.grid_remove()

class Seite_Safe_Prime_gen(Hauptmenü_grid):

    def prime_menü(self):
        Hauptmenü_grid.destroy_obj(self)
        self.title("Primenumbergen")





        def prime_test():
            primzahlen_test_result.delete(0, len(primzahlen_test_result.get()))
            prime_test_class = SafePrimeGenerator()
            prime = int(primzahlen_entry_2.get())
            if prime_test_class.millerrabinprimetest(prime) == True and prime_test_class.millerrabinprimetest(((prime - 1) // 2)) == True:
                primzahlen_test_result.insert(0, "This number is a safe prime")
            else:
                primzahlen_test_result.insert(0, "This number is not a safe prime")

        def prime_gen_windows():

            bitleght = int(primzahlen_entry_bitlenght.get())
            #assert type(bitleght) == int
            if type(bitleght) != int:
                raise Exception("type bithlenght must be int. It is ",type(bitleght))
            prime_obj = SafePrimeGenerator()
            safe_prime = prime_obj.prime_gen(bitleght)
            primzahlen_output_entry.insert(0, str(safe_prime))


        def prime_gen_over_class():

            pipe = multiprocessing.Queue()

            def prime_gen_multi_core(bitlengh):
                prime_gen = SafePrimeGenerator()
                zahl = prime_gen.prime_gen(bitlengh)
                pipe.put(zahl)

            primzahlen_entry_2.delete(0, len(primzahlen_entry_2.get()))
            prozesszahl = int(primzahlen_entry_3.get())
            prozessliste = []

            for _ in range(prozesszahl):
                processobj = multiprocessing.Process(target=prime_gen_multi_core,args=[int(primzahlen_entry_bitlenght.get())])
                processobj.start()
                prozessliste.append(processobj)

            safe_prime = pipe.get()
            for i in prozessliste:
                #i.kill()
                i.terminate()



            primzahlen_output_entry.insert(0, str(safe_prime))

        #benötigt sys lib
        def check_for_linux():
            if sys.platform == "linux":
                return True
            else:
                return False

        primzahlen_label_1 = Label(self, text="Enter the bitlenght for the prime generation")
        primzahlentest_label = Label(self,text="enter the number for safe prime check")
        trennlabel = Label(self,text="-------------------------------------------------------------")
        primzahlen_entry_bitlenght = Entry(self)
        primzahlen_entry_2 = Entry(self)
        primzahlen_entry_3 = Entry(self)


        button_prime_gen = Button(self, text="Gen prime. (takes very long with bitlenght > 1000",command=prime_gen_over_class,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_prime_test = Button(self, text="Test if input number is a safe prime",command=prime_test,activebackground=menu_and_button_color,bg=menu_and_button_color)
        primzahlen_label_2 = Label(self,text="Enter the number of cores you want to use")
        primzahlen_output_entry = Entry(self)
        primzahlen_test_result = Entry(self)

        # objgrid
        primzahlen_label_1.grid(row=1, column=0)
        primzahlen_entry_bitlenght.grid(row=2, column=0)
        primzahlen_output_entry.grid(row=4,column=0)
        trennlabel.grid(row=5,column=0)
        button_prime_gen.grid(row=3, column=0)
        primzahlentest_label.grid(row=6,column=0)
        button_prime_test.grid(row=8, column=0)
        primzahlen_entry_2.grid(row=7, column=0)
        primzahlen_test_result.grid(row=9,column=0)

        primzahlen_label_2.grid(row=1, column=1)
        primzahlen_entry_3.grid(row=2, column=1)
        primzahlen_entry_3.insert(0,"1")

        if check_for_linux() == False:
            primzahlen_label_2.grid_remove()
            primzahlen_entry_3.grid_remove()
            button_prime_gen.destroy()

            button_prime_gen = Button(self, text="Zahl erstellen.Kann ab mehr als 1000 bits länger dauern",
                                      command=prime_gen_windows,activebackground=menu_and_button_color,bg=menu_and_button_color)
            button_prime_gen.grid(row=3, column=0)

class Seite_Schnorr_sig_Prüfen(Hauptmenü_grid):
    def menü(self):
        Hauptmenü_grid.destroy_obj(self)

        self.title("Schnorrsig verifying")

        def sig_test():
            if checkboxbool.get() == False:
                ausgabe_1.delete(0, len(ausgabe_1.get()))

                signaturobj = SchnorrSig()

                primzahl = int(eingabe_01.get())
                generator = int(eingabe_02.get())
                public_key = int(eingabe_03.get())
                teilsig_1 = int(eingabe_04.get())
                teilsig_2 = int(eingabe_05.get())
                text = text_fentser.get("1.0", END)
                """hier gilt zu beachten das durch die getfunktion in der oberen zeile ein zeilen umbruch hinzugefügt wird
                 daher muss der string um die letzte positon gekürtzt werden"""
                text = text[0:(len(text) - 1)]
                ausgabe_1.insert(0,signaturobj.Signaturvery(text, teilsig_1, teilsig_2, public_key, primzahl, generator))
            if checkboxbool.get() == True:
                #statik_safe_prime_9000bit = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547
                #statik_generator = 2
                ausgabe_1.delete(0, len(ausgabe_1.get()))

                signaturobj = SchnorrSig_with_no_safty_prime_and_gen_check()

                primzahl = statik_safe_prime_9000bit
                generator = statik_generator
                public_key = int(eingabe_03.get())
                teilsig_1 = int(eingabe_04.get())
                teilsig_2 = int(eingabe_05.get())
                text = text_fentser.get("1.0", END)
                """hier gilt zu beachten das durch die getfunktion in der oberen zeile ein zeilen umbruch hinzugefügt wird
                 daher muss der string um die letzte positon gekürtzt werden"""
                text = text[0:(len(text) - 1)]
                ausgabe_1.insert(0,
                                 signaturobj.Signaturvery(text, teilsig_1, teilsig_2, public_key, primzahl, generator))

        def check_pub_key_in_text():
            gefunden = False
            pw_fur_textfile = eingabe_06_pw_fur_textfile.get()

            fileobj = open("Base.txt", "r")
            salting_string = fileobj.readline()
            pw_fur_textfile = pw_fur_textfile + salting_string
            fileobj.close()
            publik_key = eingabe_03.get()
            if len(publik_key) != 0 and len(pw_fur_textfile):
                publik_key = int(publik_key)
                cryptobj = Hash_based_blockcypher_und_Textdatei()
                text_as_dem_textfile = cryptobj.decrypt_checksumcheck_from_file(pw_fur_textfile)
                liste_von_zeilen = text_as_dem_textfile.split("\n")
                neue_liste = []
                print(liste_von_zeilen)
                for i in liste_von_zeilen:
                    if len(i) != 0:
                        neue_liste.append(i)
                liste_von_zeilen = neue_liste
                for i in liste_von_zeilen:
                    if i[0] == "|":
                        i = i[1:]
                        liste_usernaem_key = i.split(":")
                        if str(publik_key) == liste_usernaem_key[1]:
                            gefunden = True
                            nutzer_fenster = Tk()
                            nutzer_fenster.title("Username")
                            label_username = Label(nutzer_fenster,text=("Username:\n " + liste_usernaem_key[0]))
                            label_username.pack()
                            nutzer_fenster.mainloop()
                if gefunden == False:
                    nutzer_fenster = Tk()
                    nutzer_fenster.title("Username")
                    label_username = Label(nutzer_fenster, text="unknown public key")
                    label_username.pack()
                    nutzer_fenster.mainloop()
            else:
                fehler_fenster = Tk()
                fehler_fenster.title("Error")
                label_feher_fenster = Label(fehler_fenster,text="Lenght password for textfile and public key can not be zero")
                label_feher_fenster.pack()
                fehler_fenster.mainloop()




        def hide_elemets_when_statik_prime_and_gen_is_in_use():
            #statik_safe_prime_9000bit = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547
            #statik_generator = 2
            #print("boll menue schnor sig prüfen")
            if checkboxbool.get() == False:
                label_1.grid(row=1, column=0, sticky="w")
                label_2.grid(row=2, column=0, sticky="w")
                eingabe_01.grid(row=1, column=1, sticky="w")
                eingabe_02.grid(row=2, column=1, sticky="w")
                eingabe_01.delete(0,END)
                eingabe_02.delete(0,END)

            else:
                label_1.grid_forget()
                label_2.grid_forget()
                eingabe_01.grid_forget()
                eingabe_02.grid_forget()

                eingabe_01.delete(0, END)
                eingabe_02.delete(0,END)
                eingabe_01.insert(0,statik_safe_prime_9000bit)
                eingabe_02.insert(0,statik_generator)

        checkboxbool = BooleanVar()
        checkboxbool.set(True)
        checkbox_for_statik_prime_ad_geneator = Checkbutton(self,text="Static Safe-Prime and Generator",onvalue=True,offvalue=False,variable=checkboxbool,command=hide_elemets_when_statik_prime_and_gen_is_in_use)
        checkbox_for_statik_prime_ad_geneator.grid(row=0, column=0,sticky="w")




        # obj def
        label_1 = Label(self, text="Input the safe prime")
        label_2 = Label(self, text="Input the generator standard is 2")
        label_3 = Label(self, text="Input the public key")
        label_4 = Label(self, text="Input signature part 1")
        label_5 = Label(self, text="Input signature part 2")
        label_6 = Label(self, text="Input the text")
        label_7 = Label(self,text="Textfile password =>")

        eingabe_01 = Entry(self) #prime
        eingabe_02 = Entry(self) #generator
        eingabe_03 = Entry(self)
        eingabe_04 = Entry(self)
        eingabe_05 = Entry(self)
        eingabe_06_pw_fur_textfile = Entry(self)


        ausgabe_1 = Entry(self)

        text_fentser = Text(self)

        button_sig_test = Button(self, text="Start signature test", command=sig_test,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_check_for_pub_key_in_text_data = Button(self,text="Public key lookup",command=check_pub_key_in_text,bg=menu_and_button_color,activebackground=menu_and_button_color)

        # grid def
        if checkboxbool.get()== False:
            label_1.grid(row=1, column=0,sticky="w")
            label_2.grid(row=2, column=0,sticky="w")
            eingabe_01.grid(row=1, column=1, sticky="w")
            eingabe_02.grid(row=2, column=1, sticky="w")

        label_3.grid(row=3, column=0,sticky="w")
        label_4.grid(row=4, column=0,sticky="w")
        label_5.grid(row=5, column=0,sticky="w")
        label_6.grid(row=6, column=0,sticky="w")
        label_7.grid(row=9,column=1,sticky="w")


        eingabe_03.grid(row=3, column=1,sticky="w")
        eingabe_04.grid(row=4, column=1,sticky="w")
        eingabe_05.grid(row=5, column=1,sticky="w")
        eingabe_06_pw_fur_textfile.grid(row=9,column=1,sticky="e")

        text_fentser.grid(row=7, column=0,columnspan=2)

        button_sig_test.grid(row=8, column=0)
        button_check_for_pub_key_in_text_data.grid(row=8,column=1)

        ausgabe_1.grid(row=9, column=0)

        hide_elemets_when_statik_prime_and_gen_is_in_use()

class Seite_Schnorr_sig_erstellen(Hauptmenü_grid):
    def menü(self):
        Hauptmenü_grid.destroy_obj(self)

        self.title("Schnorrsig creator")

        def schnorr_unterschreiben():
            #statik_safe_prime_9000bit = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547
            #statik_generator = 2

            if checkboxbool.get() == False:
                sigobj = SchnorrSig()
                ausgabe_teilsig_1.delete(0, END)
                ausgabe_teilsig_2.delete(0, END)

                privater_key = int(eingabe_privater_key.get())
                generator = int(eingabe_generator.get())
                prime = int(eingabe_prime.get())
                text = eingabe_text.get("1.0", END)
                text = text[0:-1]
                text_anfange = "start-----------\n"
                text_ende = "\n-----------end"
                text = text_anfange + text + text_ende
                eingabe_text.delete("1.0", END)
                eingabe_text.insert("1.0", text)
                liste_teilsig_1_2 = sigobj.Textsig(text, privater_key, prime, generator)
                ausgabe_teilsig_1.insert(0, liste_teilsig_1_2[0])
                ausgabe_teilsig_2.insert(0, liste_teilsig_1_2[1])
                print(liste_teilsig_1_2)
            if checkboxbool.get() == True:
                sigobj = SchnorrSig_with_no_safty_prime_and_gen_check()
                ausgabe_teilsig_1.delete(0, END)
                ausgabe_teilsig_2.delete(0, END)

                privater_key = int(eingabe_privater_key.get())
                generator = statik_generator
                prime = statik_safe_prime_9000bit
                text = eingabe_text.get("1.0", END)
                text = text[0:-1]
                text_anfange = "start-----------\n"
                text_ende = "\n-----------end"
                text = text_anfange + text + text_ende
                eingabe_text.delete("1.0", END)
                eingabe_text.insert("1.0", text)
                liste_teilsig_1_2 = sigobj.Textsig(text, privater_key, prime, generator)
                ausgabe_teilsig_1.insert(0, liste_teilsig_1_2[0])
                ausgabe_teilsig_2.insert(0, liste_teilsig_1_2[1])
                #print(liste_teilsig_1_2)

        def copy_to_clipboard():
            if checkboxbool.get() == True:
                gesamt_string_zu_clipboard = "Static prime and generator\n" + eingabe_text.get("1.0", END) + "\nsignatur part 1:" + ausgabe_teilsig_1.get() + "\nsignatur part 2:" + ausgabe_teilsig_2.get()
                self.clipboard_clear()
                self.clipboard_append(gesamt_string_zu_clipboard)
            else:
                gesamt_string_zu_clipboard = "safe prime:" + eingabe_prime.get() + "\ngenerator:" + eingabe_generator.get() + "\n" + eingabe_text.get("1.0",END) + "\nsignatur part 1:" + ausgabe_teilsig_1.get() + "\nsignatur part 2:" + ausgabe_teilsig_2.get()
                self.clipboard_clear()
                self.clipboard_append(gesamt_string_zu_clipboard)



        def hide_elemets_when_statik_prime_and_gen_is_in_use():
            #statik_safe_prime_9000bit = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547
            #statik_generator = 2
            #print("funktionsstart bool")
            if checkboxbool.get() == False:
                label_01.grid(row=1, column=0, sticky="w")
                label_02.grid(row=2, column=0, sticky="w")
                eingabe_prime.grid(row=1, column=1, sticky="w")
                eingabe_generator.grid(row=2, column=1, sticky="w")
                eingabe_prime.delete(0,END)
                eingabe_generator.delete(0,END)

            else:
                label_01.grid_forget()
                label_02.grid_forget()
                eingabe_prime.grid_forget()
                eingabe_generator.grid_forget()

                eingabe_prime.delete(0, END)
                eingabe_generator.delete(0,END)
                eingabe_prime.insert(0,statik_safe_prime_9000bit)
                eingabe_generator.insert(0,statik_generator)

        checkboxbool = BooleanVar()
        checkboxbool.set(True)
        checkbox_for_statik_prime_ad_geneator = Checkbutton(self,text="Static Safe-Prime and Generator",onvalue=True,offvalue=False,variable=checkboxbool,command=hide_elemets_when_statik_prime_and_gen_is_in_use)
        checkbox_for_statik_prime_ad_geneator.grid(row=0, column=0,sticky="w")


        # Text, privatekey, Prime,generator: für erstellen

        # objdef

        label_01 = Label(self, text="Input safe prime")
        label_02 = Label(self, text="Input generator. Standard is 2")
        label_03 = Label(self, text="Input private key ")
        label_04 = Label(self, text="Input the message text")
        label_05 = Label(self, text="Signature part 1")
        label_06 = Label(self, text="Signature part 2")

        eingabe_prime = Entry(self)
        eingabe_generator = Entry(self)
        eingabe_privater_key = Entry(self)

        eingabe_text = Text(self)


        ausgabe_teilsig_1 = Entry(self)
        ausgabe_teilsig_2 = Entry(self)

        button_schnorr_unterschreiben = Button(self, text="Generate signature",command=schnorr_unterschreiben,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_copy_to_clipboard = Button(self,text="   Copy to clipboard   ",command=copy_to_clipboard,bg=menu_and_button_color,activebackground=menu_and_button_color)

        # grid def


        label_03.grid(row=3, column=0,sticky="w")
        label_04.grid(row=4, column=0,sticky="w")
        label_05.grid(row=7, column=0)
        label_06.grid(row=8, column=0)


        eingabe_privater_key.grid(row=3, column=1,sticky="w")

        eingabe_text.grid(row=5, column=0,columnspan=3)

        button_schnorr_unterschreiben.grid(row=7, column=3)
        button_copy_to_clipboard.grid(row=8,column=3)

        ausgabe_teilsig_1.grid(row=7, column=1)
        ausgabe_teilsig_2.grid(row=8, column=1)
        hide_elemets_when_statik_prime_and_gen_is_in_use()

class Seite_Schnorr_Schlüsselpaar_erstellen(Hauptmenü_grid):
    def menü(self):
        #Hauptmenü_grid.destroy_obj(self)
        #self.title("Schlüsselpaar erstellen")
        neues_fenster = Tk()
        neues_fenster.title("Manual Schnorr Key_Par generator")


        def schnorr_key_start():
            ausgabe_privater_key.delete(0, END)
            ausgabe_public_key.delete(0, END)
            classobj = SchnorrSig()
            safeprime = int(eingabe_safe_prime.get())
            generator = int(eingabe_generator.get())
            liste_key_paar = classobj.schorr_key_erstellen(safeprime, generator)
            ausgabe_privater_key.insert(0, liste_key_paar[0])
            ausgabe_public_key.insert(0, liste_key_paar[1])

        label_1 = Label(neues_fenster, text="Input safe prime")
        label_2 = Label(neues_fenster, text="Input generator.Standard is 2")
        label_3 = Label(neues_fenster, text="Public Key")
        label_4 = Label(neues_fenster, text="Private Key")

        eingabe_generator = Entry(neues_fenster)
        eingabe_safe_prime = Entry(neues_fenster)

        button_key_erstellen = Button(neues_fenster, text="Generate key pair",command=schnorr_key_start,activebackground=menu_and_button_color,bg=menu_and_button_color)

        ausgabe_public_key = Entry(neues_fenster)
        ausgabe_privater_key = Entry(neues_fenster)

        # grid

        label_1.grid(row=1, column=0)
        label_2.grid(row=2, column=0)
        button_key_erstellen.grid(row=3, column=0)
        label_3.grid(row=4, column=0)
        label_4.grid(row=5, column=0)

        eingabe_safe_prime.grid(row=1, column=1)
        eingabe_generator.grid(row=2, column=1)
        ausgabe_public_key.grid(row=4, column=1)
        ausgabe_privater_key.grid(row=5, column=1)
        neues_fenster.mainloop()

class Seite_Schnorr_Schlüsselpaar_erstellen_mit_statischen_var(Hauptmenü_grid):
    def menü(self):
        #Hauptmenü_grid.destroy_obj(self)
        #self.title("Schlüsselpaar erstellen")
        neues_fenster = Tk()
        neues_fenster.title("Recommended Schnorr Key_Par generator with static safeprime and generator")


        def schnorr_key_start():
            #statik_safe_prime_9000bit = 74458819126919435246068859414744618623460425798601695208877196904307247872748045672334049429894546981024999276863386005661515349393637373699807420132069292250879590277286525478810175074752117204616585672840862378323564372321730964649664396715483422613430381467948489109008157922529927485916289170043101635026601931402303498304769826159023376489747068741270344721068188619929565241626194337560037173677112247824534922145598730496466803698255549937086667818661954163558787744813931155519338120120164402284265552894811723759285234602659090352031946632960468418334701475066695550888579089336913594181306248948008728359073946483500728851803480553879823637292012068804429633299053028201079160760932682442573327611455781892346499397914390550476843745459788440761605594547947652126455297350284030618755057599672253983003186274632343383117235110328322937742473591901694287456801138520285623452847743988891700918831937840110729592476332191768312156054390422679566125514958503925082281162648428653673365014389505069651416824914731268397614123969885983786125139465112897103052543381855168558849113333902659540591376511362651082496810434130582321175717411709232283969889724218746902183394533352522481081576923698784200272947100315416212940795601993451073405011103422114679458223194110751378610176297782016397630662663946802442885276565383628397181614476440009535104864507316646837896503807017774105042120115701176859932860085950356129042891329724844388444874932561351530772012942006788790265555479286836836696203340696949153959945442382245908301968984685878476523947921308930023411412800081611309397539427811693563947636632359044291983453044802747551847491072703929314847429349629191119180559416954388473193829393396672811212310294700043354414102602310163457810390370756225355382618207541479665899820182662868337050388050156875490311693812350092825251600082353897292600267917029882527499358675547283382889028051680967190116456415405139913146232273908358196047789194274319746707967429115379253483362541726619399947672609966034284796902922210709351428453465606299995602885694732168491044560536892838035016207411993394893115712383047823949945730287421514181163055930714465053060813513119026038261896371308797532611659317881295093776302577293160691949973218110823742477660335763136093830870830594608225102882849223617954442522352808466154878504183911472734681974247571374083148364910312190384935713277246840124927115736053528184142267203598720976753052375801918648201915444689483091116894091006270051178519012374160736360457428067705136356609972357156873494504244229110036813868520939348966041482753857009674780998057220948502506035717850482183588482434809287163647349658053499792125716737613437537692454464628354651017545547
            #statik_generator = 2
            ausgabe_privater_key.delete(0, END)
            ausgabe_public_key.delete(0, END)
            classobj = SchnorrSig_with_no_safty_prime_and_gen_check()
            safeprime = statik_safe_prime_9000bit
            generator = statik_generator
            liste_key_paar = classobj.schorr_key_erstellen(safeprime, generator)
            ausgabe_privater_key.insert(0, liste_key_paar[0])
            ausgabe_public_key.insert(0, liste_key_paar[1])


        label_3 = Label(neues_fenster, text="Public Key")
        label_4 = Label(neues_fenster, text="Private Key")

        eingabe_generator = Entry(neues_fenster)
        eingabe_safe_prime = Entry(neues_fenster)

        button_key_erstellen = Button(neues_fenster, text="Generate key pair",command=schnorr_key_start,activebackground=menu_and_button_color,bg=menu_and_button_color)

        ausgabe_public_key = Entry(neues_fenster)
        ausgabe_privater_key = Entry(neues_fenster)

        # grid


        button_key_erstellen.grid(row=3, column=0,columnspan=2)
        label_3.grid(row=4, column=0)
        label_4.grid(row=5, column=0)

        ausgabe_public_key.grid(row=4, column=1)
        ausgabe_privater_key.grid(row=5, column=1)
        neues_fenster.mainloop()

class Seite_DH_Austausch_erzeugen(Hauptmenü_grid):

    def menü(self):
        neues_fenster = Tk()
        #Hauptmenü_grid.destroy_obj(self)

        neues_fenster.title("Manual DH exchange generator")

        def dh_handshake_erstellen():
            obj = dh_austausch()
            ausgabe_handshake.delete(0, END)
            ausgabe_zufalswert.delete(0, END)

            safe_prime = int(eingabe_safe_prime.get())
            generator = int(eingabe_generator.get())
            liste_zufalszahl_handshake = obj.generation_dh_austausch(safe_prime, generator)

            ausgabe_zufalswert.insert(0, liste_zufalszahl_handshake[0])
            ausgabe_handshake.insert(0, liste_zufalszahl_handshake[1])

        # obj erstellen
        label_1 = Label(neues_fenster, text="Input safe prime")
        label_2 = Label(neues_fenster, text="Input generator. Standard is 2")
        label_3 = Label(neues_fenster, text="Handshake")
        label_4 = Label(neues_fenster, text="Secret number")

        eingabe_safe_prime = Entry(neues_fenster)
        eingabe_generator = Entry(neues_fenster)

        ausgabe_handshake = Entry(neues_fenster)
        ausgabe_zufalswert = Entry(neues_fenster)

        button_dh_handshake_erstellen = Button(neues_fenster, text="Generate DH handshake",command=dh_handshake_erstellen,activebackground=menu_and_button_color,bg=menu_and_button_color)
        # grid
        label_1.grid(row=1, column=0)
        label_2.grid(row=2, column=0)
        button_dh_handshake_erstellen.grid(row=3, column=0)
        label_3.grid(row=4, column=0)
        label_4.grid(row=5, column=0)

        eingabe_safe_prime.grid(row=1, column=1)
        eingabe_generator.grid(row=2, column=1)
        ausgabe_handshake.grid(row=4, column=1)
        ausgabe_zufalswert.grid(row=5, column=1)

class Seite_DH_Austausch_erzeugen_mit_statischen_var(Hauptmenü_grid):

    def menü(self):
        neues_fenster = Tk()
        #Hauptmenü_grid.destroy_obj(self)

        neues_fenster.title("Recommended DH exchange generator with static safeprime and generator")

        def dh_handshake_erstellen():
            obj = dh_austausch_ohne_safe_prime_and_generator_check()
            ausgabe_handshake.delete(0, END)
            ausgabe_zufalswert.delete(0, END)

            safe_prime = statik_safe_prime_9000bit
            generator = statik_generator
            liste_zufalszahl_handshake = obj.generation_dh_austausch(safe_prime, generator)

            ausgabe_zufalswert.insert(0, liste_zufalszahl_handshake[0])
            ausgabe_handshake.insert(0, liste_zufalszahl_handshake[1])

        # obj erstellen
        label_3 = Label(neues_fenster, text="Handshake")
        label_4 = Label(neues_fenster, text="Secret number")


        ausgabe_handshake = Entry(neues_fenster)
        ausgabe_zufalswert = Entry(neues_fenster)

        button_dh_handshake_erstellen = Button(neues_fenster, text="Generate DH handshake",command=dh_handshake_erstellen,activebackground=menu_and_button_color,bg=menu_and_button_color)
        # grid
        button_dh_handshake_erstellen.grid(row=3, column=0)
        label_3.grid(row=4, column=0)
        label_4.grid(row=5, column=0)

        ausgabe_handshake.grid(row=4, column=1)
        ausgabe_zufalswert.grid(row=5, column=1)

class Seite_DH_Austausch_verarbeiten(Hauptmenü_grid):

    def menü(self):
        #Hauptmenü_grid.destroy_obj(self)
        neues_fenster = Tk()

        neues_fenster.title("Manual DH exchange processor")

        def handshake_verarbeitung():
            ausgabe_gemeinsame_zahl.delete(0, END)
            ogj = dh_austausch()

            safe_prime = int(eingabe_safe_prime.get())
            handshake = int(eingabe_handshake.get())
            zufalszahl = int(eingabe_zufalszahl.get())

            ausgabe_gemeinsame_zahl.insert(0, (ogj.verarbeitung_dh_austausch(safe_prime, handshake, zufalszahl)))

        label_1 = Label(neues_fenster, text="Input safe prime")
        label_2 = Label(neues_fenster, text="Input DH handshake")
        label_3 = Label(neues_fenster, text="Input secret number")
        label_4 = Label(neues_fenster, text="Output shared password")

        eingabe_safe_prime = Entry(neues_fenster)
        eingabe_handshake = Entry(neues_fenster)
        eingabe_zufalszahl = Entry(neues_fenster)

        ausgabe_gemeinsame_zahl = Entry(neues_fenster)

        button_dh_verarbeitung = Button(neues_fenster, text="Compute shared password",command=handshake_verarbeitung,activebackground=menu_and_button_color,bg=menu_and_button_color)
        # grid
        label_1.grid(row=1, column=0)
        label_2.grid(row=2, column=0)
        label_3.grid(row=3, column=0)
        button_dh_verarbeitung.grid(row=4, column=0)
        label_4.grid(row=5, column=0)

        eingabe_safe_prime.grid(row=1, column=1)
        eingabe_handshake.grid(row=2, column=1)
        eingabe_zufalszahl.grid(row=3, column=1)
        ausgabe_gemeinsame_zahl.grid(row=5, column=1)

class Seite_DH_Austausch_verarbeiten_mit_statischen_var(Hauptmenü_grid):

    def menü(self):
        #Hauptmenü_grid.destroy_obj(self)
        neues_fenster = Tk()

        neues_fenster.title("Recommended DH exchange processor with static safeprime")

        def handshake_verarbeitung():
            ausgabe_gemeinsame_zahl.delete(0, END)
            ogj = dh_austausch_ohne_safe_prime_and_generator_check()

            safe_prime = statik_safe_prime_9000bit
            handshake = int(eingabe_handshake.get())
            zufalszahl = int(eingabe_zufalszahl.get())

            ausgabe_gemeinsame_zahl.insert(0, (ogj.verarbeitung_dh_austausch(safe_prime, handshake, zufalszahl)))

        label_2 = Label(neues_fenster, text="Input DH handshake")
        label_3 = Label(neues_fenster, text="Input secret number")
        label_4 = Label(neues_fenster, text="Output shared password")


        eingabe_handshake = Entry(neues_fenster)
        eingabe_zufalszahl = Entry(neues_fenster)

        ausgabe_gemeinsame_zahl = Entry(neues_fenster)

        button_dh_verarbeitung = Button(neues_fenster, text="Compute shared password",command=handshake_verarbeitung,activebackground=menu_and_button_color,bg=menu_and_button_color)
        # grid
        label_2.grid(row=2, column=0)
        label_3.grid(row=3, column=0)
        button_dh_verarbeitung.grid(row=4, column=0)
        label_4.grid(row=5, column=0)


        eingabe_handshake.grid(row=2, column=1)
        eingabe_zufalszahl.grid(row=3, column=1)
        ausgabe_gemeinsame_zahl.grid(row=5, column=1)

class Seite_Symetrische_Text_Ver_und_Entschlüsselung(Hauptmenü_grid):

    def menü(self):
        Hauptmenü_grid.destroy_obj(self)
        self.title("symetric de/encryption")

        def verschlüsseln_und_anhängen_von_iv_und_checksum():
            """text = eingabe_text.get("1.0", END)
            text = text[0:-1]"""

            """es fehlt noch checksum in beiden funktionen"""
            #cypherobj = Hash_based_blockcypher()
            randobj = random.SystemRandom()
            salting_string = hex(randobj.getrandbits(256))[2:34]
            print("len salt")
            print(len(salting_string))
            cypherobj = Hash_based_blockcypher_mit_cbc()
            plaintext = textfeld.get("1.0",END)
            if plaintext[-1] == "\n":
                plaintext = plaintext[0:-1] #in dem textfeld ist immer ein zeilen umbruch dran dieser wird hier entfernt
            textfeld.delete("1.0",END)
            cypherobj.pw_list_gen(salting_string + password_eingabe.get())
            pw_barray_list = cypherobj.pw_array_liste
            rand_iv_block = cypherobj.get_rand_bytearray(512)

            #cyphertext_mit_iv_und_checksum = cypherobj.counter_mode_mit_rand_counter(bytearray(plaintext,"UTF-32"),)
            cyphertext_mit_iv_und_checksum = cypherobj.cbc_mode_cypher_verschlüsseln(bytearray(plaintext,"UTF-8"),rand_iv_block,True,pw_barray_list)
            cyphertext_mit_iv_und_checksum = rand_iv_block + cyphertext_mit_iv_und_checksum


            #addingpw salt
            cyphertext_mit_iv_und_checksum = bytearray.fromhex(salting_string) + cyphertext_mit_iv_und_checksum

            textfeld.insert("1.0",cyphertext_mit_iv_und_checksum.hex())
            #print("salting string encryption: ",salting_string)


        def entschlüsselung_und_prüfen_von_checksum():
            cypherobj = Hash_based_blockcypher_mit_cbc()
            cyphertext = bytearray.fromhex(textfeld.get("1.0", END)[32:])
            salting = textfeld.get("1.00",END)[:32]
            textfeld.delete("1.0", END)
            #print("salting string decryption: ", salting)
            cypherobj.pw_list_gen(salting + password_eingabe.get())
            xor_block = cyphertext[:64]
            cyphertext = cyphertext[64:]

            plaintext_array = bytearray()
            #while len(cyphertext) != 0:
            block = cyphertext
            block = cypherobj.cbc_mode_cypher_entschlüsseln(block,xor_block,cypherobj.pw_array_liste,True)

                #block = cypherobj.xor(xor_block,block)
                #plaintext_array = plaintext_array + block
                #xor_block = cyphertext[:64]
                #cyphertext = cyphertext[64:]




            plaintext = str(block,"UTF-8")
            print("plain :",plaintext_array)
            #muuss einzel per block angewaand wereen


            textfeld.insert("1.0",plaintext)


        #objdef
        label_1 = Label(root,text="Password for de/encryption")
        scrolly = Scrollbar(self)
        textfeld = Text(self,yscrollcommand=scrolly.set)
        scrolly.config(command=textfeld.yview)
        password_eingabe = Entry(self)
        button_verschlüsseln = Button(self,text="Encryption",command=verschlüsseln_und_anhängen_von_iv_und_checksum,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_entschlüsseln = Button(self,text="Decryption",command=entschlüsselung_und_prüfen_von_checksum,activebackground=menu_and_button_color,bg=menu_and_button_color)


        #griddef
        label_1.grid(row=0,column=0,sticky="w")
        password_eingabe.grid(row=0,column=0)
        button_verschlüsseln.grid(row=1,column=0,sticky="w")
        button_entschlüsseln.grid(row=1,column=0)
        textfeld.grid(row=3,column=0)
        scrolly.grid(row=3,column=1,sticky="ns")

class Seite_hash_from_data(Hauptmenü_grid):


    def hash_menu(self):
        Hauptmenü_grid.destroy_obj(self)
        self.title("Hash_menu")

        def hash_gen():
            #text_box_1.delete("1.0",END)
            path = path_entry.get()


            try:
                m = hashlib.sha256()
                data = open(path, "rb")
                aray1 = bytearray(data.read(256))
                fertig = False
                pommes = bytearray()
                m.update(aray1)
                while fertig == False:
                    aray1 = aray1 + pommes
                    pommes = bytearray(data.read(409600))
                    m.update(pommes)
                    if len(pommes) == 0:
                        fertig = True
                data.close()
                text_box_1.insert("1.0",m.hexdigest() + "\n")

            except:
                text_box_1.insert("1.0","Error please check path or read rights. \nPath subbmitted: ")

        def filepath_dialog():
            path_entry.delete(0, END)
            path_entry.insert(0, filedialog.askopenfilename())






        #obj

        label_1 = Label(self, text="Input the path to the file")
        button_1 = Button(self, text="Generate Sha-256 Hash",command=hash_gen,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_2 = Button(self,text="  Chose file  ",command=filepath_dialog,activebackground=menu_and_button_color,bg=menu_and_button_color)
        path_entry = Entry(self)

        text_box_1 = Text(self)


        #grid

        label_1.grid(row=0, column=0)
        path_entry.grid(row=0, column=1)
        button_1.grid(row=1, column=0)
        button_2.grid(row=1,column=1)
        text_box_1.grid(row=3, column=0,columnspan=20,rowspan=20,sticky="nsew")


class Seite_data_encryption_decryption(Hauptmenü_grid):

    def data_menu(self):
        Hauptmenü_grid.destroy_obj(self)
        self.title("File Decryption/Encryption")

        fileobj = Hash_based_blockcypher_mit_cbc()

        def file_encryption_cbc():

            pw_sting = str(entry_password.get())
            filepath = str(entry_filepath.get())
            filename_after_encryption = str(entry_filename_after.get())
            if len(filename_after_encryption) == 0:
                filename_after_encryption = "Data"
            #fileobj.cbc_mode_menue_funktion_encryption(pw_sting, filepath, filename_after_encryption,enty_result)
            try:
                fileobj.cbc_mode_menue_funktion_encryption(pw_sting,filepath,filename_after_encryption,enty_result)
            except Exception as message:
                #print(message)
                enty_result.delete(0,END)
                enty_result.insert(0,message)
            enty_result.delete(0,END)
            enty_result.insert(0,"success")
        def file_decryption_cbc():
            pw_sting = str(entry_password.get())
            filepath = str(entry_filepath.get())
            #filename_after_encryption = str(entry_filename_after.get())

            try:
                fileobj.cbc_mode_menue_funktion_decryption(pw_sting,filepath,str(entry_filename_after.get()),enty_result)
            except Exception as message:
                #print(message)
                enty_result.delete(0,END)
                enty_result.insert(0,message)
            enty_result.delete(0,END)
            enty_result.insert(0,"success")

        def filepath_dialog():
            entry_filepath.delete(0,END)
            entry_filepath.insert(0,filedialog.askopenfilename())
            string_for_filename_after = entry_filepath.get()
            index_counter = 0
            for i in string_for_filename_after[::-1]:
                if i == "/":
                    break
                index_counter = index_counter + 1
            string_for_filename_after = string_for_filename_after[::-1]
            string_for_filename_after = string_for_filename_after[0:index_counter]
            string_for_filename_after = string_for_filename_after[::-1]
            if string_for_filename_after[-6:] != ".crypt":
                string_for_filename_after = string_for_filename_after + ".crypt"
            else:
                string_for_filename_after = string_for_filename_after[0:-6]





            entry_filename_after.delete(0,END)
            entry_filename_after.insert(0,string_for_filename_after)


        label_01 = Label(self,text="Filename or path for the File")
        label_02 = Label(self,text="Password for de/encryption")
        label_03 = Label(self,text="Output file name for encrypt")
        entry_filepath = Entry(self)
        entry_password = Entry(self)
        button_encryption = Button(self,text="Encrypt",command=file_encryption_cbc,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_decryption = Button(self,text="Decrypt", command=file_decryption_cbc,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_filepath = Button(self, text="Chose data", command=filepath_dialog,activebackground=menu_and_button_color,bg=menu_and_button_color)
        entry_filename_after = Entry(self)
        enty_result = Entry(self,width=50)

        label_01.grid(row=0, column=0)
        entry_filepath.grid(row=0, column=1)
        label_02.grid(row=1, column=0)
        entry_password.grid(row=1, column=1)

        button_filepath.grid(row=0,column=2)
        button_encryption.grid(row=1,column=2)
        button_decryption.grid(row=2, column=2)

        entry_filename_after.grid(row=2, column=1)
        label_03.grid(row=2, column=0)
        enty_result.grid(row=3,column=0,columnspan=2)

class Seite_write_read_text_for_to_secure_safe(Hauptmenü_grid):


    def text_safe_menü(self):
        #Hauptmenü_grid.destroy_obj(self)
        neues_fenster = Tk()

        neues_fenster.title("Text safe")
        try:
            fileobj = open("Base.txt", "r")
            fileobj.close()
            #print("no exeption")
        except:
            fileobj = open("Base.txt", "w")
            randobj = random.SystemRandom()
            salting_string = str(bytearray(hex(randobj.getrandbits(256)),"UTF-8"),"UTF-8")
            fileobj.writelines("PWExtender::" + salting_string + "\n")
            fileobj.close()


        def edit_text_in_file():
            pw_string = entry_01.get()
            if len(pw_string) == 0:
                raise Exception("passwort can not be len 0")
            fileobj = open("Base.txt", "r")
            salting_string = fileobj.readline()
            pw_string = pw_string + salting_string
            fileobj.close()

            def save_edit():
                text_to_save = text_aus_data_fläche.get("1.0",END)
                hashobj = Hash_based_blockcypher_und_Textdatei()
                hashobj.overwrite_text_with_password(pw_string)
                hashobj.encryption_block_append_checksum_and_write_to_file(bytearray(text_to_save,"UTF-8"),pw_string)
                neues_fenster.destroy()




            cryptobj = Hash_based_blockcypher_und_Textdatei()
            bisheriger_text = cryptobj.decrypt_checksumcheck_from_file(pw_string)
            neues_fenster = Tk()
            scrooly = Scrollbar(neues_fenster)
            text_aus_data_fläche = Text(neues_fenster,yscrollcommand=scrooly.set)
            scrooly.config(command=text_aus_data_fläche.yview)
            scrooly.grid(row=0,column=1,sticky="ns")

            text_aus_data_fläche.grid(row=0, column=0)
            text_aus_data_fläche.insert("1.0", bisheriger_text)
            button_edit_text = Button(neues_fenster,text="save edit",command=save_edit,activebackground=menu_and_button_color,bg=menu_and_button_color)
            button_edit_text.grid(row=1,column=0,columnspan=2)


        def lese_text_aus_datei():
            pw_string = entry_01.get()
            fileobj = open("Base.txt", "r")
            salting_string = fileobj.readline()
            pw_string = pw_string + salting_string
            fileobj.close()
            cryptobj = Hash_based_blockcypher_und_Textdatei()
            if len(pw_string) == 0:
                raise Exception("len pw can not be zero")
            text_01.delete("1.0",END)
            text_01.insert("1.0",str(cryptobj.decrypt_checksumcheck_from_file(pw_string)))



        def uberschreibe_text_in_datei():
            pw_string = entry_01.get()
            fileobj = open("Base.txt", "r")
            salting_string = fileobj.readline()
            pw_string = pw_string + salting_string
            fileobj.close()
            fensteranfrage = Tk()
            fensteranfrage.title("Warning")

            def button_ja():
                hashobj = Hash_based_blockcypher_und_Textdatei()
                hashobj.overwrite_text_with_password(pw_string)
                fensteranfrage.destroy()

            def button_nein():
                fensteranfrage.destroy()

            label_anfrage = Label(fensteranfrage,text="Are you sure you want to overwrite all textentries corresponding to the password input?")
            label_anfrage.grid(row=0,column=0,columnspan=2)
            button_01 = Button(fensteranfrage,text="Yes",command=button_ja,activebackground=menu_and_button_color,bg=menu_and_button_color)
            button_02 = Button(fensteranfrage,text="No",command=button_nein,activebackground=menu_and_button_color,bg=menu_and_button_color)
            button_01.grid(row=1,column=0)
            button_02.grid(row=1,column=1)




            fensteranfrage.mainloop()


        def schreibe_text_in_datei():

            plaintext = text_01.get("1.0", END)
            pw_string = entry_01.get()
            fileobj = open("Base.txt", "r")
            salting_string = fileobj.readline()
            pw_string = pw_string + salting_string
            fileobj.close()
            hashobj = Hash_based_blockcypher_und_Textdatei()
            hashobj.encryption_block_append_checksum_and_write_to_file(bytearray(plaintext,"UTF-8"),pw_string)

        def schreibe_zufals_block_in_datei():
            try:
                nummbers_of_blocks = entry_02.get()
                nummbers_of_blocks = int(nummbers_of_blocks)
            except:
                entry_02.delete(0,END)
                entry_02.insert(0,"musst input a number here")
            cryptobj = Hash_based_blockcypher_und_Textdatei()
            cryptobj.write_rand_blocks_to_file(nummbers_of_blocks)

        def add_user_pub_key():

            def nutzer_hinzufugen():
                user_name_string = entry_01_neues_fenster_user_name.get()
                #"|" ist das makirende zeichen für ein paar im text. muss daher immer aus dem textinput der nutzer enfernt werde
                user_name_string.replace("|","")
                pubkey = int(entry_02_neues_fenster_pubkey.get())
                pw_string = entry_01.get()
                fileobj = open("Base.txt", "r")
                salting_string = fileobj.readline()
                pw_string = pw_string + salting_string
                fileobj.close()
                if len(pw_string) == 0:
                    fehler_fenster = Tk()
                    fehler_fenster.title("Error")
                    label_01_fehlerfenster = Label(fehler_fenster,text="no password was given")
                    label_01_fehlerfenster.grid(row=0,column=0)
                    fehler_fenster.mainloop()
                    raise Exception("passwort can not be len 0")

                if len(user_name_string) == 0:
                    raise Exception("username can not be len 0")
                cryptobj = Hash_based_blockcypher_und_Textdatei()
                gesamt_str = "\n" + "|" + user_name_string + ":" + str(pubkey) + "\n"
                cryptobj.encryption_block_append_checksum_and_write_to_file(bytearray(gesamt_str,"UTF-8"),pw_string)


            neue_fenster = Tk()
            neue_fenster.title("Add user/Publickey")
            label_01_neues_fenster = Label(neue_fenster,text="user name")
            label_02_neues_fenster = Label(neue_fenster,text="public key")
            entry_01_neues_fenster_user_name = Entry(neue_fenster)
            entry_02_neues_fenster_pubkey = Entry(neue_fenster)
            button_01_neues_fenster = Button(neue_fenster,text="add user/pubkey pair",command=nutzer_hinzufugen,bg=menu_and_button_color,activebackground=menu_and_button_color)

            label_01_neues_fenster.grid(row=0,column=0)
            entry_01_neues_fenster_user_name.grid(row=0,column=1)
            label_02_neues_fenster.grid(row=0,column=2)
            entry_02_neues_fenster_pubkey.grid(row=0,column=3)
            button_01_neues_fenster.grid(row=0,column=4)


            neue_fenster.mainloop



        label_01 = Label(neues_fenster,text="Password").grid(row=0,column=0,sticky="")
        label_02 = Label(neues_fenster,text="Number of random blocks").grid(row=3,column=0,sticky="w")
        entry_01 = Entry(neues_fenster)
        entry_01.grid(row=0,column=1,sticky="w")
        entry_02 = Entry(neues_fenster)
        entry_02.grid(row=3,column=1,sticky="w")
        text_01 = Text(neues_fenster)
        #text_01.grid(row=2,column=0,columnspan=2)



        button_01 = Button(neues_fenster,text="Read from safe file",command=lese_text_aus_datei,activebackground=menu_and_button_color,bg=menu_and_button_color)
        #button_01.grid(row=1,column=0,sticky="w")
        button_02 = Button(neues_fenster,text="Write random blocks to file",command=schreibe_zufals_block_in_datei,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_02.grid(row=3,column=2)
        #button_03 = Button(neues:fenster, text="Write Text to file", command=schreibe_text_in_datei,activebackground=menu_and_button_color,bg=menu_and_button_color)
        #button_03.grid(row=1,column=0,sticky="e")
        button_04 = Button(neues_fenster,text=" Overwrite text ",command=uberschreibe_text_in_datei,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_04.grid(row=1,column=1)
        button_05 = Button(neues_fenster,text="   Edit/read text   ",command=edit_text_in_file,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_05.grid(row=1,column=2)
        button_06 = Button(neues_fenster,text="Add a user/pubkey",command=add_user_pub_key,activebackground=menu_and_button_color,bg=menu_and_button_color)
        button_06.grid(row=1, column=0, sticky="e")

        neues_fenster.mainloop()

class Seite_Licence_and_info(Hauptmenü_grid):

    def info_menu(self):
        Hauptmenü_grid.destroy_obj(self)
        self.title("License and Info")


        file = open("licence.txt","r")
        big_string = file.read()

        textbox_01 = Text(self)
        textbox_01.grid(row=0,column=0)
        textbox_01.insert("1.0",big_string)

def seitenwechsel():
    for i in root.grid_slaves():
        print(i)
def seitenwechsel2():
    for i in root.grid_slaves():
        root.forget(i)



#fileobj = licence_file_check()
#fileobj = fileobj.licence_file_check()
#variante ohne licence
if TRUE == True:
    root = Tk()
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    Hauptmenü_grid.menü_1(root)
    Seite_Schnorr_sig_erstellen.menü(root)




root.mainloop()
