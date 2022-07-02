/**
 * Copyright (c) 2010-2021 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.e3dc.internal;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.e3dc.internal.rscp.RSCPData;
import org.openhab.binding.e3dc.internal.rscp.RSCPFrame;
import org.openhab.binding.e3dc.internal.rscp.RSCPTag;
import org.openhab.binding.e3dc.internal.rscp.util.AES256Helper;
import org.openhab.binding.e3dc.internal.rscp.util.BouncyAES256Helper;
import org.openhab.binding.e3dc.internal.rscp.util.ByteUtils;
import org.openhab.binding.e3dc.internal.rscp.util.FrameLoggerHelper;
import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.library.types.QuantityType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.library.unit.Units;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link E3DCConnector} is responsible for handling the connection to E3DC, frame sending and receiving.
 *
 * @author Brendon Votteler - Initial Contribution
 * @author Björn Brings - Rework for OpenHAB
 */
public class E3DCConnector {
    private static final int maxRetries = 3;
    private static final long sleepMillisBeforeRetry = 5000;
    private static final Logger logger = LoggerFactory.getLogger(E3DCConnector.class);

    private @Nullable E3DCConfiguration config;
    private @Nullable E3DCHandler handle;
    private AES256Helper aesHelper;
    private Socket socket;
    private Instant lastHistoryPollTime = null;
    private ZoneId deviceTimeZone = null;
    private long deviceTimeShiftMillis = 0L;

    public E3DCConnector(@NonNull E3DCHandler handle, E3DCConfiguration config) {
        this.handle = handle;
        this.config = config;

        final String aesPwd = config.getRscppassword(); // password set on E3DC for AES
        aesHelper = BouncyAES256Helper.createBouncyAES256Helper(aesPwd);

        connectE3DC();
    }

    /**
     * Connect & authenticate
     */
    public void connectE3DC() {
        if (config != null) {
            final String address = config.getIp();
            final int port = config.getPort();
            final String user = config.getWebusername(); // typically email address
            final String pwd = config.getWebpassword(); // used to log into E3DC portal

            logger.debug("Open connection to server {}:{} ...", address, port);
            try {
                openConnection(address, port);
                logger.debug("Sending authentication frame to server...");
                byte[] authFrame = E3DCRequests.buildAuthenticationMessage(user, pwd);
                Integer bytesSent = sendFrameToServer(aesHelper::encrypt, authFrame);
                byte[] decBytesReceived = receiveFrameFromServer(aesHelper::decrypt);
                logger.debug("Authentication: Received {} decrypted bytes from server.", decBytesReceived.length);
            } catch (UnknownHostException e) {
                handle.updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                        "Could not connect to host");
            } catch (IOException e) {
                handle.updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR, "Connection error");
            } catch (Throwable e) {
                logger.error("Connection error", e);
                handle.updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR, "Connection error");
            }

            waitRequest();

        }
    }

    public void setPowerLimitsUsed(Boolean value) {
        setBoolValue(RSCPTag.TAG_EMS_REQ_SET_POWER_SETTINGS, RSCPTag.TAG_EMS_POWER_LIMITS_USED, value);
    }

    public void setMaxDischargePower(int value) {
        setuint32CharValue(RSCPTag.TAG_EMS_REQ_SET_POWER_SETTINGS, RSCPTag.TAG_EMS_MAX_DISCHARGE_POWER, value);
    }

    public void setMaxChargePower(int value) {
        setuint32CharValue(RSCPTag.TAG_EMS_REQ_SET_POWER_SETTINGS, RSCPTag.TAG_EMS_MAX_CHARGE_POWER, value);
    }

    public void setDischargeStartPower(int value) {
        setuint32CharValue(RSCPTag.TAG_EMS_REQ_SET_POWER_SETTINGS, RSCPTag.TAG_EMS_DISCHARGE_START_POWER, value);
    }

    public void setWeatherRegulatedChargeEnable(Boolean value) {
        char charValue = (char) (value ? 1 : 0);
        setCharValue(RSCPTag.TAG_EMS_REQ_SET_POWER_SETTINGS, RSCPTag.TAG_EMS_WEATHER_REGULATED_CHARGE_ENABLED,
                charValue);
    }

    public void setPowerSaveEnable(Boolean value) {
        char charValue = (char) (value ? 1 : 0);
        setCharValue(RSCPTag.TAG_EMS_REQ_SET_POWER_SETTINGS, RSCPTag.TAG_EMS_POWERSAVE_ENABLED, charValue);
    }

    public void setEmergencyPowerMode(int value) {
        setCharValue(RSCPTag.TAG_EMS_REQ_SET_EMERGENCY_POWER, (char) value);
    }

    /* primitive setters */

    public void setCharValue(RSCPTag tag, char value) {
        logger.trace("setCharValue tag:{} value:{}", tag.name(), (int) value);
        byte[] reqFrame = E3DCRequests.buildRequestSetFrame(tag, value);
        handleRequest(reqFrame, respFrame -> handleE3DCResponse(respFrame));
    }

    public void setStringValue(RSCPTag tag, String value) {
        logger.trace("setStringValue tag:{} value:{}", tag.name(), value);
        byte[] reqFrame = E3DCRequests.buildRequestSetFrame(tag, value);
        handleRequest(reqFrame, respFrame -> handleE3DCResponse(respFrame));
    }

    public void setTimestampValue(RSCPTag tag, Instant value) {
        logger.trace("setTimestampValue tag:{} value:{}", tag.name(), value.toString());
        byte[] reqFrame = E3DCRequests.buildRequestSetFrame(tag, value);
        handleRequest(reqFrame, respFrame -> handleE3DCResponse(respFrame));
    }

    public void setuint32CharValue(RSCPTag containerTag, RSCPTag tag, int value) {
        logger.trace("setuint32CharValue container:{} tag:{} value:{}", containerTag.name(), tag.name(), value);
        byte[] reqFrame = E3DCRequests.buildRequestSetFrame(containerTag, tag, value);
        handleRequest(reqFrame, respFrame -> handleE3DCResponse(respFrame));
    }

    public void setCharValue(RSCPTag containerTag, RSCPTag tag, char value) {
        logger.trace("setCharValue container:{} tag:{} value:{}", containerTag.name(), tag.name(), (int) value);
        byte[] reqFrame = E3DCRequests.buildRequestSetFrame(containerTag, tag, value);
        handleRequest(reqFrame, respFrame -> handleE3DCResponse(respFrame));
    }

    public void setBoolValue(RSCPTag containerTag, RSCPTag tag, Boolean value) {
        logger.trace("setBoolValue container:{} tag:{} value:{}", containerTag.name(), tag.name(), value);
        byte[] reqFrame = E3DCRequests.buildRequestSetFrame(containerTag, tag, value);
        handleRequest(reqFrame, respFrame -> handleE3DCResponse(respFrame));
    }

    /* periodic requests */

    public void requestE3DCData() {
        byte[] reqFrame = E3DCRequests.buildRequestFrame();
        handleRequest(reqFrame, respFrame -> handleE3DCResponse(respFrame));
        ZoneOffset tzOffset = ZoneOffset.UTC;
        Instant deviceDatetime = Instant.now();
        if (deviceTimeZone != null) {
            tzOffset = deviceTimeZone.getRules().getOffset(Instant.now());
            // sync time
            /*
             * if (deviceTimeShiftMillis > 5000) {
             * logger.info("device time shift is {}s -- syncing", ((float) deviceTimeShiftMillis) / 1000);
             * waitRequest();
             * // TAG_INFO_REQ_SET_TIME --> error 0x07 (unknown tag)
             * // TAG_INFO_REQ_SET_TIME_UTC --> error 0x02 (access denied)
             * setTimestampValue(RSCPTag.TAG_INFO_REQ_SET_TIME_UTC, Instant.now());
             * // .plus(tzOffset.getTotalSeconds(), ChronoUnit.SECONDS));
             * // returns TAG_INFO_SET_TIME_ZONE=BOOL(false) - meaning "unchanged"?
             * // setStringValue(RSCPTag.TAG_INFO_REQ_SET_TIME_ZONE, "Europe/Paris");
             * }
             */
        }
        deviceDatetime = deviceDatetime.plus(deviceTimeShiftMillis, ChronoUnit.MILLIS);
        // if a new time interval has started then get the accumulated data for the last interval
        // month
        int historySize = 6; // DEBUG
        if ((lastHistoryPollTime == null)
                || (lastHistoryPollTime.atZone(tzOffset).getMonth() != deviceDatetime.atZone(tzOffset).getMonth())) {
            // get start of last full month
            // use Calendar -- ChronoUnit.MONTHS is not supported for arithmetic in Instant
            Calendar cal = Calendar.getInstance();
            cal.setTime(Date.from(deviceDatetime));
            cal = truncateToMonth(cal);
            Instant iEnd = cal.getTime().toInstant();
            cal.add(Calendar.MONTH, -historySize);
            Instant iStart = cal.getTime().toInstant();
            waitRequest();
            logger.trace("Requesting monthly history from {} to {}", iStart.toString(), iEnd.toString());
            reqFrame = E3DCRequests.buildRequestFrameHistory(timeToDevice(iStart), Calendar.MONTH, historySize);
            handleRequest(reqFrame, respFrame -> handleHistoryResponse(respFrame, iStart, iEnd, ChronoUnit.MONTHS));
        }
        // day
        historySize = 7; // DEBUG
        if ((lastHistoryPollTime == null) || (lastHistoryPollTime.atZone(tzOffset).getDayOfMonth() != deviceDatetime
                .atZone(tzOffset).getDayOfMonth())) {
            // get start of last full day
            Instant iEnd = deviceDatetime.truncatedTo(ChronoUnit.DAYS); // .minus((long) k * historySize,
                                                                        // ChronoUnit.DAYS);
            Instant iStart = iEnd.minus((long) historySize, ChronoUnit.DAYS);
            waitRequest();
            logger.trace("Requesting daily history from {} to {}", iStart.toString(), iEnd.toString());
            reqFrame = E3DCRequests.buildRequestFrameHistory(timeToDevice(iStart), Calendar.DAY_OF_MONTH, historySize);
            handleRequest(reqFrame, respFrame -> handleHistoryResponse(respFrame, iStart, iEnd, ChronoUnit.DAYS));
        }
        // hour
        historySize = 12; // DEBUG
        if ((lastHistoryPollTime == null)
                || (lastHistoryPollTime.atZone(tzOffset).getHour() != deviceDatetime.atZone(tzOffset).getHour())) {
            // get start of last full hour
            Instant iEnd = deviceDatetime.truncatedTo(ChronoUnit.HOURS);
            Instant iStart = iEnd.minus((long) historySize, ChronoUnit.HOURS);
            waitRequest();
            logger.trace("Requesting hourly history from {} to {}", iStart.toString(), iEnd.toString());
            reqFrame = E3DCRequests.buildRequestFrameHistory(timeToDevice(iStart), Calendar.HOUR, historySize);
            handleRequest(reqFrame, respFrame -> handleHistoryResponse(respFrame, iStart, iEnd, ChronoUnit.HOURS));
            lastHistoryPollTime = deviceDatetime; // comment this line for debugging
        }
    }

    private void waitRequest() {
        // TODO: is there a better way to detect connection readiness?
        try {
            Thread.sleep(500);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    /* time helper functions */

    private Instant timeToDevice(Instant systemTime) {
        /*
         * necessary or not ?
         * if (deviceTimeZone != null) {
         * ZoneOffset tzOffset = deviceTimeZone.getRules().getOffset(systemTime);
         * return systemTime.plus(tzOffset.getTotalSeconds(), ChronoUnit.SECONDS);
         * }
         */
        return systemTime;
    }

    /**
     * Returns a copy of instant with the specified number of time units added
     */
    private Instant addTime(Instant instant, int num, ChronoUnit unit) {
        if (ChronoUnit.MONTHS == unit) {
            // ChronoUnit.MONTHS is not supported for arithmetic in Instant
            Calendar cal = Calendar.getInstance();
            cal.setTime(Date.from(instant));
            cal.add(Calendar.MONTH, num);
            return cal.getTime().toInstant();
        } else {
            return instant.plus((long) num, unit);
        }
    }

    private Instant truncateToMonth(Instant instant) {
        Calendar cal = Calendar.getInstance();
        cal.setTime(Date.from(instant));
        return truncateToMonth(cal).getTime().toInstant();
    }

    private Calendar truncateToMonth(Calendar cal) {
        // ChronoUnit.MONTHS is not supported for arithmetic in Instant
        int year = cal.get(Calendar.YEAR);
        int month = cal.get(Calendar.MONTH);
        cal = Calendar.getInstance();
        cal.setTimeInMillis(0); // cal.clear(); ?
        cal.set(year, month, 1);
        return cal;
    }

    /* request handling */

    public void handleRequest(byte[] reqFrame, Consumer<RSCPFrame> consumer) {
        if (isNotConnected()) {
            connectE3DC();
        }
        logger.trace("Unencrypted frame to send: {}", ByteUtils.byteArrayToHexString(reqFrame));
        Integer bytesSent = sendFrameToServer(aesHelper::encrypt, reqFrame);
        byte[] decBytesReceived = receiveFrameFromServer(aesHelper::decrypt);
        logger.trace("Decrypted frame received: {}", ByteUtils.byteArrayToHexString(decBytesReceived));
        RSCPFrame responseFrame = RSCPFrame.builder().buildFromRawBytes(decBytesReceived);

        consumer.accept(responseFrame);
        FrameLoggerHelper.logFrame(responseFrame);
    }

    public void handleE3DCResponse(RSCPFrame responseFrame) {
        List<RSCPData> dataList = responseFrame.getData();
        for (RSCPData data : dataList) {
            handleUpdateData(data);
        }
    }

    public void handleHistoryResponse(RSCPFrame responseFrame, Instant startTime, Instant endTime, ChronoUnit unit) {
        logger.trace("handleHistoryResponse");
        // convert from device time to system time - DONT this will store period data at non-full hour/day/...
        // startTime = startTime.minus(deviceTimeShiftMillis, ChronoUnit.MILLIS);
        // endTime = endTime.minus(deviceTimeShiftMillis, ChronoUnit.MILLIS);
        List<RSCPData> containerList = responseFrame.getData();
        for (RSCPData container : containerList) {
            String dt = container.getDataTag().name();
            logger.trace("  got tag {}", dt);
            if (ChronoUnit.HOURS == unit) {
                handleHistoryContainerData(container, startTime, endTime, unit, "Hour");
            } else if (ChronoUnit.DAYS == unit) {
                handleHistoryContainerData(container, startTime, endTime, unit, "Day");
            } else if (ChronoUnit.MONTHS == unit) {
                handleHistoryContainerData(container, startTime, endTime, unit, "Month");
            } else if (ChronoUnit.YEARS == unit) {
                handleHistoryContainerData(container, startTime, endTime, unit, "Year");
            }
        }
    }

    public void handleHistoryContainerData(RSCPData data, Instant startTime, Instant endTime, ChronoUnit unit,
            String sInterval) {
        logger.trace("handleHistoryContainerData for {} {}", sInterval, startTime.toString());
        List<RSCPData> dataList = data.getContainerData();
        // DEBUG
        Map<String, String[]> results = new HashMap<String, String[]>();
        int count = 0;
        // calculate actual startTime since the delivered history data may be shorter than requested.
        int nPoints = dataList.size() - 1;
        startTime = addTime(endTime, -nPoints, unit);
        for (RSCPData container : dataList) {
            String dt = container.getDataTag().name();
            logger.trace("  got tag {}", dt);
            if ("TAG_DB_SUM_CONTAINER".equals(dt)) {
                List<RSCPData> containedDataList = container.getContainerData();
                Instant dateTime = startTime;
                for (RSCPData containedData : containedDataList) {
                    String tagName = containedData.getDataTag().name();
                    if ("TAG_DB_GRAPH_INDEX".equals(tagName)) {
                        // will be -1 for TAG_DB_SUM_CONTAINER
                    } else {
                        // handleUpdateHistoryData(containedData, dateTime, interval);
                    }
                }
            } else if ("TAG_DB_VALUE_CONTAINER".equals(dt)) {
                List<RSCPData> containedDataList = container.getContainerData();
                Instant dateTime = addTime(startTime, count, unit);
                for (RSCPData containedData : containedDataList) {
                    String tagName = containedData.getDataTag().name();
                    if ("TAG_DB_GRAPH_INDEX".equals(tagName)) {
                        float index = containedData.getValueAsFloat().orElse(0.0f);
                        // the graph index has a strange logic. rather count the value containers
                    } else {
                        handleUpdateHistoryData(containedData, dateTime, sInterval);
                    }
                    // DEBUG
                    if (results.get(tagName) == null) {
                        results.put(tagName, new String[nPoints]);
                    }
                    results.get(tagName)[count] = containedData.getValueAsString().toString();
                }
                ++count;
            }
        }
        logger.trace("  table for {}", results.keySet().toString());
        for (String tagName : results.keySet()) {
            String[] col = results.get(tagName);
            String out = "";
            for (int i = 0; i < nPoints; ++i) {
                out += "\t" + col[i];
            }
            logger.trace("  " + tagName + ":\t" + out);
        }
    }

    public void handleUpdateData(RSCPData data) {
        String dt = data.getDataTag().name();

        if ("TAG_EMS_POWER_PV".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPowerPV,
                    new QuantityType<>(data.getValueAsInt().orElse(-1), Units.WATT));
        } else if ("TAG_EMS_POWER_BAT".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPowerBat,
                    new QuantityType<>(data.getValueAsInt().orElse(-1), Units.WATT));
        } else if ("TAG_EMS_POWER_HOME".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPowerHome,
                    new QuantityType<>(data.getValueAsInt().orElse(-1), Units.WATT));
        } else if ("TAG_EMS_POWER_GRID".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPowerGrid,
                    new QuantityType<>(data.getValueAsInt().orElse(-1), Units.WATT));
        } else if ("TAG_EMS_POWER_ADD".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPowerAdd,
                    new QuantityType<>(data.getValueAsInt().orElse(-1), Units.WATT));
        } else if ("TAG_EMS_BAT_SOC".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_BatterySOC,
                    new QuantityType<>(data.getValueAsInt().orElse(-1), Units.PERCENT));
        } else if ("TAG_EMS_SELF_CONSUMPTION".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_SelfConsumption,
                    new QuantityType<>(data.getValueAsFloat().orElse((float) -1.0), Units.PERCENT));
        } else if ("TAG_EMS_AUTARKY".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_Autarky,
                    new QuantityType<>(data.getValueAsFloat().orElse((float) -1.0), Units.PERCENT));
        } else if ("TAG_PM_DATA".equals(dt)) {
            List<RSCPData> containedDataList = data.getContainerData();
            for (RSCPData containedData : containedDataList) {
                handleUpdatePMData(containedData);
            }
        } else if ("TAG_EMS_GET_POWER_SETTINGS".equals(dt)) {
            List<RSCPData> containedDataList = data.getContainerData();
            for (RSCPData containedData : containedDataList) {
                handleUpdatePowerSettingsData(containedData);
            }
        } else if ("TAG_EMS_SET_POWER_SETTINGS".equals(dt)) {
            List<RSCPData> containedDataList = data.getContainerData();
            for (RSCPData containedData : containedDataList) {
                handleUpdatePowerSettingsData(containedData);
            }
        } else if ("TAG_EMS_EMERGENCY_POWER_STATUS".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_EmergencyPowerStatus,
                    new DecimalType((long) data.getValueAsLong().orElse(-1L)));
        } else if ("TAG_EP_IS_GRID_CONNECTED".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_GridConnected,
                    OnOffType.from(data.getValueAsBool().orElse(false)));
        } else if ("TAG_INFO_SW_RELEASE".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_SWRelease,
                    new StringType(data.getValueAsString().orElse("ERR")));
        } else if ("TAG_INFO_TIME_ZONE".equals(dt)) {
            String zoneId = data.getValueAsString().orElse(null);
            logger.trace("device time zone is '{}'", zoneId);
            if (zoneId != null) {
                deviceTimeZone = ZoneId.of(zoneId);
            }
            if (deviceTimeZone == null) {
                logger.warn("cannot parse device time zone '{}'", zoneId);
            }
        } else if ("TAG_INFO_UTC_TIME".equals(dt)) {
            Instant deviceDateTimeUtc = data.getValueAsInstant().orElse(null);
            if (deviceDateTimeUtc != null) {
                logger.trace("device date time is {}", deviceDateTimeUtc.toString());
                deviceTimeShiftMillis = ChronoUnit.MILLIS.between(Instant.now(), deviceDateTimeUtc);
                if (deviceTimeShiftMillis > 2000) {
                    logger.info("device time shift is {}s", ((float) deviceTimeShiftMillis) / 1000);
                }
            }
        }
    }

    private void handleUpdatePMData(RSCPData data) {
        String dt = data.getDataTag().name();

        if ("TAG_PM_ENERGY_L1".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMEnergyL1,
                    new QuantityType<>(data.getValueAsDouble().orElse(-1.0), Units.WATT_HOUR));
        } else if ("TAG_PM_ENERGY_L2".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMEnergyL2,
                    new QuantityType<>(data.getValueAsDouble().orElse(-1.0), Units.WATT_HOUR));
        } else if ("TAG_PM_ENERGY_L3".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMEnergyL3,
                    new QuantityType<>(data.getValueAsDouble().orElse(-1.0), Units.WATT_HOUR));
        } else if ("TAG_PM_POWER_L1".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMPowerL1,
                    new QuantityType<>(data.getValueAsDouble().orElse(-1.0), Units.WATT));
        } else if ("TAG_PM_POWER_L2".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMPowerL2,
                    new QuantityType<>(data.getValueAsDouble().orElse(-1.0), Units.WATT));
        } else if ("TAG_PM_POWER_L3".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMPowerL3,
                    new QuantityType<>(data.getValueAsDouble().orElse(-1.0), Units.WATT));
        } else if ("TAG_PM_VOLTAGE_L1".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMVoltageL1,
                    new QuantityType<>(data.getValueAsFloat().orElse((float) -1.0), Units.VOLT));
        } else if ("TAG_PM_VOLTAGE_L2".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMVoltageL2,
                    new QuantityType<>(data.getValueAsFloat().orElse((float) -1.0), Units.VOLT));
        } else if ("TAG_PM_VOLTAGE_L3".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_CurrentPMVoltageL3,
                    new QuantityType<>(data.getValueAsFloat().orElse((float) -1.0), Units.VOLT));
        } else if ("TAG_PM_MODE".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_Mode, new DecimalType((long) data.getValueAsLong().get()));
        }
    }

    private void handleUpdatePowerSettingsData(RSCPData data) {
        String dt = data.getDataTag().name();
        logger.debug("handleUpdatePowerSettingsData  : {}: {}", dt, data.getValueAsString());

        if ("TAG_EMS_POWER_LIMITS_USED".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_PowerLimitsUsed,
                    OnOffType.from(data.getValueAsBool().orElse(false)));
        } else if ("TAG_EMS_RES_TAG_EMS_POWER_LIMITS_USED".equals(dt)) {
            // maybe update TAG_EMS_POWER_LIMITS_USED...?
        } else if ("TAG_EMS_MAX_DISCHARGE_POWER".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_MaxDischarge,
                    new QuantityType<>(data.getValueAsInt().get(), Units.WATT));
        } else if ("TAG_EMS_RES_MAX_DISCHARGE_POWER".equals(dt)) {
            // maybe update TAG_EMS_MAX_DISCHARGE_POWER...?
        } else if ("TAG_EMS_MAX_CHARGE_POWER".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_MaxCharge,
                    new QuantityType<>(data.getValueAsInt().get(), Units.WATT));
        } else if ("TAG_EMS_RES_MAX_CHARGE_POWER".equals(dt)) {
            // maybe update TAG_EMS_MAX_CHARGE_POWER...?
        } else if ("TAG_EMS_DISCHARGE_START_POWER".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_DischargeStart,
                    new QuantityType<>(data.getValueAsInt().get(), Units.WATT));
        } else if ("TAG_EMS_RES_DISCHARGE_START_POWER".equals(dt)) {
            // maybe update TAG_EMS_DISCHARGE_START_POWER...?
        } else if ("TAG_EMS_WEATHER_REGULATED_CHARGE_ENABLED".equals(dt)) {
            handle.updateState(E3DCBindingConstants.CHANNEL_WeatherRegulatedCharge,
                    OnOffType.from(data.getValueAsBool().orElse(false)));
        } else if ("TAG_EMS_RES_WEATHER_REGULATED_CHARGE_ENABLE".equals(dt)) {
            // maybe update TAG_EMS_WEATHER_REGULATED_CHARGE_ENABLED...?
        } else if ("TAG_EMS_POWERSAVE_ENABLED".equals(dt)) {
            boolean result = data.getValueAsBool().orElse(false);

            handle.updateState(E3DCBindingConstants.CHANNEL_PowerSave, OnOffType.from(result));
        } else if ("TAG_EMS_RES_POWERSAVE_ENABLED".equals(dt)) {
            // maybe update TAG_EMS_POWERSAVE_ENABLED...?
        }
    }

    private void handleUpdateHistoryData(RSCPData data, Instant dateTime, String interval) {
        String dt = data.getDataTag().name();
        logger.debug("handleUpdateHistoryData  : {}: {}", dt, data.getValueAsString());

        if ("TAG_DB_GRAPH_INDEX".equals(dt)) {
            // handled by caller
        } else if ("TAG_DB_BAT_POWER_IN".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_BatteryPowerIn + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_BAT_POWER_OUT".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_BatteryPowerOut + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_DC_POWER".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_DCPower + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_GRID_POWER_IN".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_GridPowerIn + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_GRID_POWER_OUT".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_GridPowerOut + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_CONSUMPTION".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_Consumption + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_PM_0_POWER".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_PM0Power + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_PM_1_POWER".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_PM1Power + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.WATT_HOUR),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_BAT_CHARGE_LEVEL".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_BatteryChargeLevel + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.PERCENT),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_BAT_CYCLE_COUNT".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_BatteryCycleCount + "-" + interval,
                    new DecimalType((double) data.getValueAsFloat().orElse(0.0f)), dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_CONSUMED_PRODUCTION".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_Consumed_Production + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.PERCENT),
                    dateTime.atZone(ZoneOffset.UTC));
        } else if ("TAG_DB_AUTARKY".equals(dt)) {
            handle.updateHistoricState(E3DCBindingConstants.CHANNEL_HISTORY_AutarkyLevel + "-" + interval,
                    new QuantityType<>(data.getValueAsFloat().orElse(0.0f), Units.PERCENT),
                    dateTime.atZone(ZoneOffset.UTC));
        }
    }

    private boolean isNotConnected() {
        return socket == null || socket.isClosed();
    }

    public void close() {
        try {
            if (socket != null) {
                socket.close();
                socket = null;
            }
        } catch (IOException e) {
            logger.info("Couldn't close connection: {}", e);
        }
    }

    public void openConnection(String ipAddress, int port, int maxRetries, long sleepMillisBeforeRetry)
            throws IOException {
        socket = null;
        int retries = 0;
        while (isNotConnected() && retries++ < maxRetries) {
            try {
                socket = new Socket(ipAddress, port);
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(10000);
            } catch (UnknownHostException e) {
                socket.close();
                throw e;
            } catch (IOException e) {
                socket.close();
                if (retries < maxRetries) {
                    try {
                        Thread.sleep(sleepMillisBeforeRetry);
                    } catch (Exception ex) {
                        // ignore
                    }
                }
            } catch (Exception e) {
                throw e;
            }
        }

        if (socket == null) {
            // retries exhausted, still no connection
            throw new RuntimeException("Failed to establish connection to server.");
        }
    }

    public void openConnection(String ipAddress, int port) throws IOException {
        openConnection(ipAddress, port, maxRetries, sleepMillisBeforeRetry);
    }

    /**
     * Send a encrypt and send a byte array through a provided socket.
     *
     * @param socket The socket to write to.
     * @param encryptFunc A function to encrypt the provided frame.
     * @param frame The unencrypted frame as byte array.
     * @return Either an exception or the number of bytes sent.
     */
    public Integer sendFrameToServer(Function<byte[], byte[]> encryptFunc, byte[] frame) {
        if (isNotConnected()) {
            throw new IllegalStateException("Not connected to server. Must connect to server first before sending.");
        }
        // TODO: check if ready
        try {
            byte[] encryptedFrame = encryptFunc.apply(frame);
            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            dOut.write(encryptedFrame);
            dOut.flush();
            logger.debug("Finished sending {} encrypted bytes.", encryptedFrame.length);
            return encryptedFrame.length;
        } catch (Exception e) {
            logger.error("Error while encrypting and sending frame.", e);
        }
        return null;
    }

    /**
     * Receive a frame from a socket and decrypted it.
     *
     * @param socket A socket to read from.
     * @param decryptFunc A function to decrypt the received byte array.
     * @return Either an exception or the decrypted response as byte array.
     */
    public byte[] receiveFrameFromServer(Function<byte[], byte[]> decryptFunc) {
        if (isNotConnected()) {
            throw new IllegalStateException("Not connected to server. Must connect to server first before sending.");
        }

        try {
            int totalBytesRead = 0;
            DataInputStream dIn = new DataInputStream(socket.getInputStream());
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] data = new byte[4096];
            do {
                int bytesRead = dIn.read(data, 0, data.length);
                if (bytesRead == -1) {
                    logger.warn("Socket closed unexpectedly by server.");
                    break;
                }
                logger.debug("Received {} bytes, append to buffer... ", bytesRead);
                buffer.write(data, 0, bytesRead);
                totalBytesRead += bytesRead;
            } while (dIn.available() > 0);

            logger.debug("Finished reading {} bytes.", totalBytesRead);
            buffer.flush();

            byte[] decryptedData = decryptFunc.apply(buffer.toByteArray());
            logger.debug("Decrypted frame data.");

            return decryptedData;
        } catch (Exception e) {
            logger.error("Error while receiving and decrypting frame.", e);
        }
        return null;
    }
}
