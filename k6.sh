#!/bin/bash

k6 run --vus 1000 --duration 1m k6.js
