# Схема протокола голосования с одной Центральной комиссией на базе «слепой» подписи

import math
from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15

class CIK:
    '''Класс ЦИК'''
    def __init__(self) -> None:
        '''
        1. Список ключей ЦИК
        2. Список правомочных избирателей
        3. Список публичный ключей из ЦСК (избирателей)
        4. Список доступных кандидатов
        5. Список бюллетеней
        '''
        self.cik_keys = RSA.generate(1024)
        self.list_voters = {1:None, 2:None, 3:None, 4:None, 5:None, 6:None, 7:None, 8:None}
        self.list_from_csk = None
        self.list_candidates = {1:0, 2:0, 3:0, 4:0, 5:0, 6:0}
        self.list_bulletins = {}
        print(f"Список правомочных избирателей (по id): {list(self.list_voters.keys())}")
    
    def get_data_from_voter(self, voter_data: tuple, pub_key_voter: RSA) -> bool:
        '''Получение информации от избирателя
        1. Проверка id в списке правомочных избирателей
        2. Проверка первичной регистрации избирателя с id
        3. Проверка ЭЦП избирателя к скрытой метке (хэш-образа)
        '''
        id_user = voter_data[0]
        mark_blind = voter_data[1]
        signature_ds = voter_data[2]

        if (id_user in self.list_voters.keys() and not(self.list_voters.get(id_user, 0) is not None)):
            self.list_voters[id_user] = pub_key_voter
            verifier = pkcs1_15.new(pub_key_voter)
            try:
                verifier.verify(SHA256.new(mark_blind.to_bytes(256, 'big')), signature_ds)
            except:
                print(f"Обнаржуен жулик с id={id_user}! Его голос не будет учтен.")
                return False
            
            return True
        else:
            print(f"Обнаржуен жулик с id={id_user}! Его голос не будет учтен.")
            return False
    
    def signature(self, value: int, key: int, mod: int) -> int:
        '''Формирование ЭЦП'''
        signature = pow(value, key, mod)
        return signature

    def get_sign(self, voter_data: tuple) -> tuple:
        '''Получение ЭЦП'''
        mark_blind = voter_data[1]
        signature_ds = self.signature(mark_blind, self.cik_keys.d, self.cik_keys.n)
        return mark_blind, signature_ds
    
    def decode_data(self, list_ds: list) -> str:
        '''Расшифровка данных от избирателя'''
        cipher = PKCS1_OAEP.new(cik.cik_keys)
        result = ""
        for i in list_ds:
            result += cipher.decrypt(i).decode()
        return result
    
    def verify_and_vote(self, result: str) -> None:
        '''Проверка и учет голоса избирателя
        1. Проверка подписи DS к метке M
        2. Публикация M и B или изменение голоса
        3. Публикация результатов голосования
        '''
        split_result = result.split(";")

        if (split_result[1] != 'None'):
            mark = int(split_result[0])
            ds = int(split_result[1])
            current_vote = int(split_result[2])
            mode = int(split_result[3])

            if (current_vote in self.list_candidates):
                answer = pow(ds, cik.cik_keys.e, cik.cik_keys.n) % cik.cik_keys.n

                if (answer == mark):
                    if (mode == 2):
                        old_vote = self.list_bulletins[mark]
                        self.list_candidates[old_vote] -= 1
                        print(f'Голос избирателя {mark} за {old_vote} кандидата отменен.')

                    self.list_bulletins[mark] = current_vote
                    print(f'Голос избирателя {mark} за {current_vote} кандидата учтен.')
                
                self.list_candidates[current_vote] += 1
            else:
                print(f"Кандидат с id={current_vote} отсутствует в избирательном бланке.")
        else:
            print("Вас нет в списке избирателей.")

class CSK:
    '''Класс ЦСК'''
    def __init__(self, cik_pub_key) -> None:
        '''
        1. Список публичных ключей ЦИК
        2. Список публичных ключей избирателей
        '''
        self.cik_pub_key = cik_pub_key
        self.list_voters_pub_keys = {}

class Voter:
    '''Класс Избирателя'''
    def __init__(self, csk_pub_key: RSA, id: int) -> None:
        '''
        1. Публичный ключ ЦСК (от ЦИК)
        2. Список ключей текущего избирателя
        3. Метка избирателя
        4. Затемняющий множитель
        5. id избирателя
        6. Голос текущего избирателя
        7. ЭЦП к метке от ЦИК
        '''
        self.csk_pub_key = csk_pub_key
        self.voter_keys = RSA.generate(1024)
        self.mark = number.getRandomRange(10000, 50000)
        self.r = number.getRandomRange(10000, 50000)
        self.id = id
        self.vote = 0
        self.ds = None

    def hide_mark(self):
        '''Скрытие метки избирателя'''
        blind = pow(self.r, self.csk_pub_key.e, self.csk_pub_key.n)
        mark_blind = blind * self.mark % self.csk_pub_key.n

        signer = pkcs1_15.new(self.voter_keys)
        signature_ds = signer.sign(SHA256.new(mark_blind.to_bytes(256, 'big')))

        return self.id, mark_blind, signature_ds
    
    def get_unblind_ds(self, cik_data: tuple) -> int:
        '''Снятие затемняющего множителя с ЭЦП комисии'''
        signature_ds = cik_data[1]
        ds = number.inverse(self.r, self.csk_pub_key.n) * signature_ds
        return ds
    
    def encrypt_data(self, ds: int, mode: int) -> list:
        '''Шифрование данных для отправки в ЦИК
        1. Формируется строка с данными
        2. Строка шифруется блоками по 40 байт
        '''
        cipher = PKCS1_OAEP.new(voter.csk_pub_key.public_key())
        encrypt_data = []

        data_for_encrypt = str(self.mark) + ";" + str(ds) + ";" + str(self.vote) + ";" + str(mode)
        block_size = 40

        for i in range(0, math.ceil(len(data_for_encrypt)/block_size)):
            if (len(data_for_encrypt) >= block_size + i * block_size):
                encrypt_data.append(cipher.encrypt(data_for_encrypt[block_size * i : block_size + i * block_size].encode()))
            else:
                end_of_data = data_for_encrypt[block_size * i : len(data_for_encrypt)]
                encrypt_data.append(cipher.encrypt(end_of_data.encode()))

        return encrypt_data

if (__name__ == "__main__"):
    cik = CIK()
    csk = CSK(cik.cik_keys)
    voters = []

    print("\n")
    add_voters = True
    while add_voters:
        id_voter = int(input("Введите id избирателя (0 - выход): "))
        if id_voter == 0:
            break
        
        voter = Voter(csk.cik_pub_key, id_voter)
        voters.append(voter)

    # Обмен ключами ЦИК и избирателей через ЦСК
    csk.list_voters_pub_keys = voters
    cik.list_from_csk = csk.list_voters_pub_keys

    print("\n")
    for voter in voters:
        data_to_cik = voter.hide_mark()
        
        if (cik.get_data_from_voter(data_to_cik, voter.voter_keys.public_key())):
            data_to_voter = cik.get_sign(data_to_cik)

            voter.ds = voter.get_unblind_ds(data_to_voter)
            voter.vote = number.getRandomRange(1,6)

            encrypt_data = voter.encrypt_data(voter.ds, 1)

            decoded_data = cik.decode_data(encrypt_data)
            cik.verify_and_vote(decoded_data)

    change_votes = True
    while change_votes:
        vote = input("\nКто-то желает изменить голос? (да/нет): ")

        if (vote == 'да'):
            data = input("Введите id и новый голос (id,голос): ").split(",")
            index = 0

            for user in range(0, len(voters)):
                if (voters[user].id == int(data[0])):
                    index = user
                    break

            voters[index].vote = int(data[1])
            encrypt_data = voters[index].encrypt_data(voters[index].ds, 2)

            decoded_data = cik.decode_data(encrypt_data)
            cik.verify_and_vote(decoded_data)

        else: 
            change_votes = False

    print(f"Результаты голосования: {cik.list_candidates}")