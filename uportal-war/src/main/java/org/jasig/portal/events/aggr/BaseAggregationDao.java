/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.portal.events.aggr;

import java.util.Collection;
import java.util.List;

import org.jasig.portal.events.aggr.groups.AggregatedGroupMapping;
import org.joda.time.DateTime;

/**
 * Base DAO APIs shared between all {@link BaseAggregation} implementation DAOs
 * 
 * @author Eric Dalquist
 * @param <T> Aggregation type
 */
public interface BaseAggregationDao<T extends BaseAggregation> {
    /**
     * Aggregations in a date range for a specified interval and group(s) ordered by date/time
     * 
     * @param start the start {@link DateTime} of the range, inclusive
     * @param end the end {@link DateTime} of the range, exclusive
     * @param interval the aggregation interval to query for
     * @param aggregatedGroupMapping The group(s) to get data for
     */
    List<T> getAggregations(DateTime start, DateTime end, AggregationInterval interval, AggregatedGroupMapping aggregatedGroupMapping, AggregatedGroupMapping... aggregatedGroupMappings);

    /**
     * @return All aggregations for the date, time and interval
     */
    Collection<T> getAggregationsForInterval(DateDimension dateDimension, TimeDimension timeDimension, AggregationInterval interval);
    
    /**
     * Get a specific aggregation 
     */
    T getAggregation(DateDimension dateDimension, TimeDimension timeDimension, AggregationInterval interval, AggregatedGroupMapping aggregatedGroup);
}