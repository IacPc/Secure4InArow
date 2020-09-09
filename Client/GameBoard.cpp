//
// Created by Laura Lemmi on 07/09/2020.
//

#include "GameBoard.h"
#include "../Libraries/Constant.h"
#include <iostream>

GameBoard::GameBoard() {

    for(int i = 0; i < ROWSNUMBER; i++) {
        for(int j = 0; j < COLUMNSNUMBER; j++)
            gameMatrix[i][j] = -1;
    }

}

GameBoard::~GameBoard() {

    for(int i = 0; i < ROWSNUMBER; i++) {
        for(int j = 0; j < COLUMNSNUMBER; j++)
            gameMatrix[i][j] = -1;
    }
}


int GameBoard::insertCoordinateInBoard(uint8_t x, uint8_t y, int value) {

    if(x < 1 || x > 6 || y < 1 || y > 7) {
        std::cout << "Error! Coordinate not valid" << std::endl;
        return -1;
    }
    x--;
    y--;

    if(gameMatrix[x][y] != -1){
        std::cout<<"Error! That position was not empty!"<<std::endl;
        return -1;
    }

    gameMatrix[x][y] = value;
/*
    for(int i = 0; i < ROWSNUMBER; i++) {
        for (int j = 0; j < COLUMNSNUMBER; j++)
            std::cout << gameMatrix[i][j]<< "  ";
        std::cout<<std::endl;
    }*/
    return 0;

}

int GameBoard::insertMyMove(uint8_t x, uint8_t y) {

    int ret = insertCoordinateInBoard(x, y, 0);

    if(ret == -1) {
        std::cout<<"Some error occured"<<std::endl;
        return ret;
    }
    //check if I won
    if(gameFinished(0)) {
        return 1;
    }
    //check if I lost
    if(gameFinished(1)) {
        return 2;
    }
    return 0;
}

int GameBoard::insertOpponentMove(uint8_t x, u_int8_t y) {
    int ret = insertCoordinateInBoard(x, y, 1);

    if(ret == -1) {
        std::cout<<"Some error occured"<<std::endl;
        return ret;
    }
    //check if I won
    if(gameFinished(0)) {
        return 1;
    }
    //check if I lost
    if(gameFinished(1)) {
        return 2;
    }
    return 0;
}

bool GameBoard::gameFinished(int valueToCheck) {

    for(int i = 0; i < ROWSNUMBER; i++){    //rows
        for(int j = 0; j < COLUMNSNUMBER; j++){     //colums
                //check horizontal
            if (j + 3 < COLUMNSNUMBER) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i][j + 1] == valueToCheck &&
                    this->gameMatrix[i][j + 2] == valueToCheck &&
                    this->gameMatrix[i][j + 3] == valueToCheck) {
                    return true;
                }
            }

            // check vertical
            if (i + 3 < ROWSNUMBER) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i + 1][j] == valueToCheck &&
                    this->gameMatrix[i + 2][j] == valueToCheck &&
                    this->gameMatrix[i + 3][j] == valueToCheck) {
                    return true;
                }
            }

            //check diagonal from top left corner
            if (i + 3 < ROWSNUMBER && j + 3 < COLUMNSNUMBER) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i + 1][j + 1] == valueToCheck &&
                    this->gameMatrix[i + 2][j + 2] == valueToCheck &&
                    this->gameMatrix[i + 3][j + 3] == valueToCheck) {
                    return true;
                }
            }

            //check diagonal from top right corner
            if (i + 3 < ROWSNUMBER && j - 3 >= 0) {
                if (this->gameMatrix[i][j] == valueToCheck &&
                    this->gameMatrix[i + 1][j - 1] == valueToCheck &&
                    this->gameMatrix[i + 2][j - 2] == valueToCheck &&
                    this->gameMatrix[i + 3][j - 3] == valueToCheck) {
                    return true;
                }
            }
        }
    }
    return false;
}



std::ostream &operator<<(std::ostream &out,const GameBoard& g) {

    string rowColors("echo \"||");

    unsigned int index = 0;
    unsigned int nextPos = g.CELLWIDTH-1;
    unsigned int totalNumberOfequals = (g.CELLWIDTH +2)* g.GAMEBOARDCOLUMNS +2;

    for(int j = 0;j < totalNumberOfequals;j++){
        if(j == nextPos){
            out<<index+1;
            index++;
            nextPos += 2*(g.CELLWIDTH-1) -1;
        }
        else{
            out<<" ";
        }

    }
    out<<endl;

    for(int i =0;i< (g.CELLWIDTH +2)* g.GAMEBOARDCOLUMNS +2;i++){
        out<<"=";
    }
    out<<endl;

    for (int i = 0; i < g.GAMEBOARDROWS; ++i)
    {
        for (int j = 0; j < g.GAMEBOARDCOLUMNS; ++j){
            switch(g.gameMatrix[i][j]){
                case -1:rowColors.append(g.BLACKPIXEL);break;
                case 0 :rowColors.append(g.GREENPIXEL);break;
                case 1 :rowColors.append(g.REDPIXEL);break;
            }
        }

        rowColors.append("\"");
        system(rowColors.c_str());

        string temp(rowColors);
        temp.replace(temp.end()-1,temp.end(),std::to_string(i+1));
        temp.append("\"");

        system(temp.c_str());
        system(rowColors.c_str());

        rowColors.clear();
        temp.clear();
        rowColors.append("echo \"||");

        for(int k =0;k< (g.CELLWIDTH +2)* g.GAMEBOARDCOLUMNS +2;k++){
            out<<"=";
        }
        out<<endl;

    }
    return out;
}



