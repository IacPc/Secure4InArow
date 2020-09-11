//
// Created by Laura Lemmi on 07/09/2020.
//

#ifndef ALL_GAMEBOARD_H
#define ALL_GAMEBOARD_H

#include <cstdint>
#include <iostream>
#include "../Libraries/Constant.h"
using namespace std;
class GameBoard {
private:
    static const unsigned int GAMEBOARDROWS = 6;
    static const unsigned int GAMEBOARDCOLUMNS =  7;
    static const unsigned int CELLWIDTH = 5;
    const char REDPIXEL[18] =   "\e[41m     \e[0m||" ;
    const char GREENPIXEL[18] = "\e[42m     \e[0m||" ;
    const char BLACKPIXEL[17] = "\e[0m     \e[0m||" ;
    int gameMatrix[GAMEBOARDROWS][GAMEBOARDCOLUMNS];
    string myUserName;
    string opponentUserName;

    int insertCoordinateInBoard(uint8_t, uint8_t, int);
    bool gameFinished(int);
public:
    GameBoard(const char*,const char*);
    int insertOpponentMove(uint8_t, uint8_t);
    int insertMyMove(uint8_t, uint8_t);
    friend std::ostream & operator << (std::ostream &out,const GameBoard &g);
    ~GameBoard();


};


#endif //ALL_GAMEBOARD_H
